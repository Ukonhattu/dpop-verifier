use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::{Algorithm, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::DpopError;
use crate::jwk::{decoding_key_from_p256_xy, thumbprint_ec_p256};
use crate::replay::{ReplayContext, ReplayStore};

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
    // Split compact JWS
    let mut it = dpop_compact_jws.split('.');
    let (h_b64, _p_b64, _s_b64) = match (it.next(), it.next(), it.next()) {
        (Some(h), Some(_), Some(_)) if it.next().is_none() => (h, (), ()),
        _ => return Err(DpopError::MalformedJws),
    };

    // Decode JOSE header
    let hdr: DpopHeader = {
        let bytes = B64.decode(h_b64).map_err(|_| DpopError::MalformedJws)?;
        serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?
    };
    if hdr.typ != "dpop+jwt" {
        return Err(DpopError::MalformedJws);
    }
    if hdr.alg != "ES256" {
        return Err(DpopError::UnsupportedAlg);
    }
    if hdr.jwk.kty != "EC" || hdr.jwk.crv != "P-256" {
        return Err(DpopError::BadJwk("expect EC P-256"));
    }

    // Verify signature only (claims checked manually)
    let key = decoding_key_from_p256_xy(&hdr.jwk.x, &hdr.jwk.y)?;
    let mut v = Validation::new(Algorithm::ES256);
    v.validate_exp = false;
    v.validate_nbf = false;
    v.validate_aud = false;
    let data = jsonwebtoken::decode::<serde_json::Value>(dpop_compact_jws, &key, &v)
        .map_err(|_| DpopError::InvalidSignature)?;
    let c = &data.claims;

    // Required claims
    let jti = c
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("jti"))?;
    let iat = c
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or(DpopError::MissingClaim("iat"))?;
    let htm = c
        .get("htm")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("htm"))?;
    let htu = c
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("htu"))?;

    if !htm.eq_ignore_ascii_case(expected_htm) {
        return Err(DpopError::HtmMismatch);
    }
    if !equal_htu(expected_htu, htu) {
        return Err(DpopError::HtuMismatch);
    }

    // Optional ath
    if let Some(at) = maybe_access_token {
        let want = B64.encode(Sha256::digest(at.as_bytes()));
        let got = c
            .get("ath")
            .and_then(|v| v.as_str())
            .ok_or(DpopError::MissingAth)?;
        if got != want {
            return Err(DpopError::AthMismatch);
        }
    }

    // Freshness
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if iat > now + opts.future_skew_secs {
        return Err(DpopError::FutureSkew);
    }
    if now - iat > opts.max_age_secs {
        return Err(DpopError::Stale);
    }

    // Replay prevention
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
        let res = crate::jwk::decoding_key_from_p256_xy(&bad_x, &good_y);
        assert!(res.is_err(), "expected error for bad x");

        // 32-byte x, 33-byte y
        let good_x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
        let bad_y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 33]);
        let res = crate::jwk::decoding_key_from_p256_xy(&good_x, &bad_y);
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
