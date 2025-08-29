use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::DpopError;
use crate::jwk::{thumbprint_ec_p256, verifying_key_from_p256_xy};
use crate::replay::{ReplayContext, ReplayStore};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

#[derive(Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: Jwk,
}
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    pub max_age_secs: i64,
    pub future_skew_secs: i64,
}
impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            max_age_secs: 300,
            future_skew_secs: 120,
        }
    }
}

#[derive(Debug)]
pub struct VerifiedDpop {
    pub jkt: String,
    pub jti: String,
    pub iat: i64,
}

/// Verify DPoP proof and record the jti to prevent replays.
pub async fn verify_proof<S: ReplayStore + ?Sized>(
    store: &mut S,
    dpop_compact_jws: &str,
    expected_htu: &str,
    expected_htm: &str,
    maybe_access_token: Option<&str>,
    opts: VerifyOptions,
) -> Result<VerifiedDpop, DpopError> {
    // 1) Split Compact JWS
    let mut it = dpop_compact_jws.split('.');
    let (h_b64, p_b64, s_b64) = match (it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s)) if it.next().is_none() => (h, p, s),
        _ => return Err(DpopError::MalformedJws),
    };

    // 2) Parse JOSE header
    let hdr: DpopHeader = {
        let bytes = B64.decode(h_b64).map_err(|_| DpopError::MalformedJws)?;
        serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?
    };
    if hdr.typ != "dpop+jwt" {
        return Err(DpopError::MalformedJws);
    }
    // JOSE algorithm must be ES256 (P-256 + SHA-256)
    if hdr.alg != "ES256" {
        return Err(DpopError::UnsupportedAlg);
    }
    if hdr.jwk.kty != "EC" || hdr.jwk.crv != "P-256" {
        return Err(DpopError::BadJwk("expect EC P-256"));
    }

    // 3) Build verifying key from JWK x/y
    let vk: VerifyingKey = verifying_key_from_p256_xy(&hdr.jwk.x, &hdr.jwk.y)?;

    // 4) Verify ECDSA signature over "<header>.<payload>"
    let signing_input = {
        let mut s = String::with_capacity(h_b64.len() + 1 + p_b64.len());
        s.push_str(h_b64);
        s.push('.');
        s.push_str(p_b64);
        s
    };

    let sig_bytes = B64.decode(s_b64).map_err(|_| DpopError::InvalidSignature)?;
    // JOSE requires raw r||s (64 bytes) for ES256. Convert to DER for p256 parser.
    let der = raw_rs_to_der(&sig_bytes).ok_or(DpopError::InvalidSignature)?;
    let sig = Signature::from_der(&der).map_err(|_| DpopError::InvalidSignature)?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| DpopError::InvalidSignature)?;

    // 5) Claims
    let claims: serde_json::Value = {
        let bytes = B64.decode(p_b64).map_err(|_| DpopError::MalformedJws)?;
        serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?
    };

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("jti"))?;
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or(DpopError::MissingClaim("iat"))?;
    let htm = claims
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("htm"))?;
    let htu = claims
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("htu"))?;

    if !htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DpopError::HtmMismatch);
    }
    if !equal_htu(expected_htu, htu) {
        return Err(DpopError::HtuMismatch);
    }

    // 6) Optional ath (only when an access token is being presented)
    if let Some(at) = maybe_access_token {
        let want = B64.encode(Sha256::digest(at.as_bytes()));
        let got = claims
            .get("ath")
            .and_then(|v| v.as_str())
            .ok_or(DpopError::MissingAth)?;
        if got != want {
            return Err(DpopError::AthMismatch);
        }
    }

    // 7) Freshness (iat)
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if iat > now + opts.future_skew_secs {
        return Err(DpopError::FutureSkew);
    }
    if now - iat > opts.max_age_secs {
        return Err(DpopError::Stale);
    }

    // 8) Replay prevention (store SHA-256(jti))
    let mut hasher = Sha256::new();
    hasher.update(jti.as_bytes());
    let mut jti_hash = [0u8; 32];
    jti_hash.copy_from_slice(&hasher.finalize());

    let jkt = thumbprint_ec_p256(&hdr.jwk.x, &hdr.jwk.y)?;
    let ok = store
        .insert_once(
            jti_hash,
            ReplayContext {
                jkt: Some(&jkt),
                htm: Some(htm),
                htu: Some(htu),
                iat,
            },
        )
        .await?;
    if !ok {
        return Err(DpopError::Replay);
    }

    Ok(VerifiedDpop {
        jkt,
        jti: jti.to_string(),
        iat,
    })
}

// Minimal tolerant comparison: strip query/fragment; case-insensitive host.
fn equal_htu(a: &str, b: &str) -> bool {
    fn trim(u: &str) -> &str {
        u.split(['?', '#']).next().unwrap_or(u)
    }
    trim(a).eq_ignore_ascii_case(trim(b))
}

/// Convert JOSE raw r||s (64 bytes) to ASN.1/DER for p256 parser.
fn raw_rs_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }
    let (r, s) = raw.split_at(32);

    fn enc_int(mut v: &[u8]) -> Vec<u8> {
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..]; // strip leading zeros
        }
        let mut out = v.to_vec();
        if !out.is_empty() && (out[0] & 0x80) != 0 {
            let mut z = Vec::with_capacity(out.len() + 1);
            z.push(0);
            z.extend_from_slice(&out);
            out = z;
        }
        out
    }

    let r_enc = enc_int(r);
    let s_enc = enc_int(s);

    let len = 2 + r_enc.len() + 2 + s_enc.len();
    let mut der = Vec::with_capacity(2 + len);
    der.push(0x30);
    if len < 128 {
        der.push(len as u8);
    } else {
        der.push(0x81);
        der.push(len as u8);
    }
    der.push(0x02);
    der.push(r_enc.len() as u8);
    der.extend_from_slice(&r_enc);
    der.push(0x02);
    der.push(s_enc.len() as u8);
    der.extend_from_slice(&s_enc);
    Some(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::thumbprint_ec_p256;

    #[test]
    fn equal_htu_ignores_query_and_fragment() {
        assert!(equal_htu(
            "https://ex.example.com/api/token?x=1#frag",
            "HTTPS://EX.EXAMPLE.COM/api/token"
        ));
        assert!(equal_htu(
            "http://host/path/segment?foo=bar",
            "http://HOST/path/segment"
        ));
        assert!(!equal_htu(
            "https://ex.example.com/api/token",
            "https://ex.example.com/api/token/extra"
        ));
    }

    #[test]
    fn thumbprint_has_expected_length_and_no_padding() {
        // 32 zero bytes -> base64url = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (43 chars)
        let x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let y = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let t1 = thumbprint_ec_p256(x, y).expect("thumbprint");
        let t2 = thumbprint_ec_p256(x, y).expect("thumbprint");
        // deterministic and base64url w/out '=' padding; sha256 -> 43 chars
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 43);
        assert!(!t1.contains('='));
    }

    #[test]
    fn decoding_key_rejects_wrong_sizes() {
        // 31-byte x (trimmed), 32-byte y
        let bad_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 31]);
        let good_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let res = crate::jwk::verifying_key_from_p256_xy(&bad_x, &good_y);
        assert!(res.is_err(), "expected error for bad y");

        // 32-byte x, 33-byte y
        let good_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let bad_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 33]);
        let res = crate::jwk::verifying_key_from_p256_xy(&good_x, &bad_y);
        assert!(res.is_err(), "expected error for bad y");
    }

    #[tokio::test]
    async fn replay_store_trait_basic() {
        use async_trait::async_trait;
        use std::collections::HashSet;

        struct MemoryStore(HashSet<[u8; 32]>);

        #[async_trait]
        impl ReplayStore for MemoryStore {
            async fn insert_once(
                &mut self,
                jti_hash: [u8; 32],
                _ctx: ReplayContext<'_>,
            ) -> Result<bool, DpopError> {
                Ok(self.0.insert(jti_hash))
            }
        }

        let mut s = MemoryStore(HashSet::new());
        let first = s
            .insert_once(
                [42u8; 32],
                ReplayContext {
                    jkt: Some("j"),
                    htm: Some("POST"),
                    htu: Some("https://ex"),
                    iat: 0,
                },
            )
            .await
            .unwrap();
        let second = s
            .insert_once(
                [42u8; 32],
                ReplayContext {
                    jkt: Some("j"),
                    htm: Some("POST"),
                    htu: Some("https://ex"),
                    iat: 0,
                },
            )
            .await
            .unwrap();
        assert!(first);
        assert!(!second); // replay detected
    }
}
