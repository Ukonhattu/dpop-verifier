use crate::uri::{normalize_htu, normalize_method};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
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
            future_skew_secs: 5,
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
    let mut it = dpop_compact_jws.split('.');
    let (h_b64, p_b64, s_b64) = match (it.next(), it.next(), it.next()) {
        (Some(h), Some(p), Some(s)) if it.next().is_none() => (h, p, s),
        _ => return Err(DpopError::MalformedJws),
    };

    // Decode JOSE header (as Value first, to reject private 'd')
    let hdr: DpopHeader = {
        let bytes = B64.decode(h_b64).map_err(|_| DpopError::MalformedJws)?;
        let val: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?;
        // MUST NOT include private JWK material
        if val.get("jwk").and_then(|j| j.get("d")).is_some() {
            return Err(DpopError::BadJwk("jwk must not include 'd'"));
        }
        serde_json::from_value(val).map_err(|_| DpopError::MalformedJws)?
    };

    if hdr.typ != "dpop+jwt" {
        return Err(DpopError::MalformedJws);
    }
    // JOSE algorithm must be ES256 (P-256 + SHA-256)

    match hdr.alg.as_str() {
        "ES256" => { /* ok */ }
        // "EdDSA" if cfg!(feature = "eddsa") => { /* ok */ } <-- Will maybe add later
        "none" => return Err(DpopError::InvalidAlg("none".into())),
        a if a.starts_with("HS") => return Err(DpopError::InvalidAlg(a.into())),
        other => return Err(DpopError::UnsupportedAlg(other.into())),
    }
    if hdr.jwk.kty != "EC" || hdr.jwk.crv != "P-256" {
        return Err(DpopError::BadJwk("expect EC P-256"));
    }

    let vk: VerifyingKey = verifying_key_from_p256_xy(&hdr.jwk.x, &hdr.jwk.y)?;

    // Verify ECDSA signature over "<header>.<payload>"
    let signing_input = {
        let mut s = String::with_capacity(h_b64.len() + 1 + p_b64.len());
        s.push_str(h_b64);
        s.push('.');
        s.push_str(p_b64);
        s
    };

    let sig_bytes = B64.decode(s_b64).map_err(|_| DpopError::InvalidSignature)?;
    // JOSE (JWS ES256) requires raw r||s (64 bytes). Do NOT accept DER.
    if sig_bytes.len() != 64 {
        return Err(DpopError::InvalidSignature);
    }
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| DpopError::InvalidSignature)?;
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| DpopError::InvalidSignature)?;

    let claims: serde_json::Value = {
        let bytes = B64.decode(p_b64).map_err(|_| DpopError::MalformedJws)?;
        serde_json::from_slice(&bytes).map_err(|_| DpopError::MalformedJws)?
    };

    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::MissingClaim("jti"))?;
    if jti.len() > 512 {
        return Err(DpopError::JtiTooLong);
    }
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

    // Strict method & URI checks (normalize both sides, then exact compare)
    let want_htm = normalize_method(expected_htm)?; // e.g., "GET"
    let got_htm = normalize_method(htm)?; // from claims
    if got_htm != want_htm {
        return Err(DpopError::HtmMismatch);
    }

    let want_htu = normalize_htu(expected_htu)?; // scheme://host[:port]/path (no q/frag)
    let got_htu = normalize_htu(htu)?;
    if got_htu != want_htu {
        return Err(DpopError::HtuMismatch);
    }

    // Optional ath (only when an access token is being presented)
    if let Some(at) = maybe_access_token {
        // Compute expected SHA-256 bytes of the exact token octets:
        let want = Sha256::digest(at.as_bytes());
        // Decode provided ath (must be base64url no-pad):
        let got_b64 = claims
            .get("ath")
            .and_then(|v| v.as_str())
            .ok_or(DpopError::MissingAth)?;
        let got = B64
            .decode(got_b64.as_bytes())
            .map_err(|_| DpopError::AthMalformed)?;
        // Constant-time compare of raw digests:
        if got.len() != want.len() || bool::from(got.ct_eq(&want[..])) == false {
            return Err(DpopError::AthMismatch);
        }
    }

    // Freshness (iat)
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if iat > now + opts.future_skew_secs {
        return Err(DpopError::FutureSkew);
    }
    if now - iat > opts.max_age_secs {
        return Err(DpopError::Stale);
    }

    // Replay prevention (store SHA-256(jti))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::thumbprint_ec_p256;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use rand_core::OsRng;

    // ---- helpers ----------------------------------------------------------------

    fn gen_es256_key() -> (SigningKey, String, String) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let ep = vk.to_encoded_point(false);
        let x = B64.encode(ep.x().unwrap());
        let y = B64.encode(ep.y().unwrap());
        (sk, x, y)
    }

    fn make_jws(
        sk: &SigningKey,
        header_val: serde_json::Value,
        claims_val: serde_json::Value,
    ) -> String {
        let h = serde_json::to_vec(&header_val).unwrap();
        let p = serde_json::to_vec(&claims_val).unwrap();
        let h_b64 = B64.encode(h);
        let p_b64 = B64.encode(p);
        let signing_input = format!("{h_b64}.{p_b64}");
        let sig: Signature = sk.sign(signing_input.as_bytes());
        let s_b64 = B64.encode(sig.to_bytes());
        format!("{h_b64}.{p_b64}.{s_b64}")
    }

    #[derive(Default)]
    struct MemoryStore(std::collections::HashSet<[u8; 32]>);

    #[async_trait::async_trait]
    impl ReplayStore for MemoryStore {
        async fn insert_once(
            &mut self,
            jti_hash: [u8; 32],
            _ctx: ReplayContext<'_>,
        ) -> Result<bool, DpopError> {
            Ok(self.0.insert(jti_hash))
        }
    }
    // ---- tests ------------------------------------------------------------------
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
    #[tokio::test]
    async fn verify_valid_es256_proof() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j1","iat":now,"htm":"GET","htu":"https://api.example.com/resource"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let res = verify_proof(
            &mut store,
            &jws,
            "https://api.example.com/resource",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await;
        assert!(res.is_ok(), "{res:?}");
    }

    #[tokio::test]
    async fn method_normalization_allows_lowercase_claim() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j2","iat":now,"htm":"get","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        assert!(
            verify_proof(
                &mut store,
                &jws,
                "https://ex.com/a",
                "GET",
                None,
                VerifyOptions::default()
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn htu_normalizes_dot_segments_and_default_ports_and_strips_qf() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // claim has :443, dot-segment, query and fragment
        let claim_htu = "https://EX.COM:443/a/../b?q=1#frag";
        let expect_htu = "https://ex.com/b";
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j3","iat":now,"htm":"GET","htu":claim_htu});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        assert!(
            verify_proof(
                &mut store,
                &jws,
                expect_htu,
                "GET",
                None,
                VerifyOptions::default()
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn htu_path_case_mismatch_fails() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j4","iat":now,"htm":"GET","htu":"https://ex.com/API"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/api",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::HtuMismatch);
    }

    #[tokio::test]
    async fn alg_none_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // still sign, but "alg":"none" must be rejected before/independent of signature
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"none","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j5","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::InvalidAlg(_));
    }

    #[tokio::test]
    async fn alg_hs256_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"HS256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"j6","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::InvalidAlg(_));
    }

    #[tokio::test]
    async fn jwk_with_private_d_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        // inject "d" (any string) -> must be rejected
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y,"d":"AAAA"}});
        let p = serde_json::json!({"jti":"j7","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::BadJwk(_));
    }

    #[tokio::test]
    async fn ath_binding_ok_and_mismatch_and_padded_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let at = "access.token.string";
        let ath = B64.encode(Sha256::digest(at.as_bytes()));
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});

        // OK
        let p_ok = serde_json::json!({"jti":"j8","iat":now,"htm":"GET","htu":"https://ex.com/a","ath":ath});
        let jws_ok = make_jws(&sk, h.clone(), p_ok);
        let mut store = MemoryStore::default();
        assert!(
            verify_proof(
                &mut store,
                &jws_ok,
                "https://ex.com/a",
                "GET",
                Some(at),
                VerifyOptions::default()
            )
            .await
            .is_ok()
        );

        // Mismatch
        let p_bad = serde_json::json!({"jti":"j9","iat":now,"htm":"GET","htu":"https://ex.com/a","ath":ath});
        let jws_bad = make_jws(&sk, h.clone(), p_bad);
        let mut store2 = MemoryStore::default();
        let err = verify_proof(
            &mut store2,
            &jws_bad,
            "https://ex.com/a",
            "GET",
            Some("different.token"),
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::AthMismatch);

        // Padded ath should be rejected as malformed (engine is URL_SAFE_NO_PAD)
        let ath_padded = format!("{ath}==");
        let p_pad = serde_json::json!({"jti":"j10","iat":now,"htm":"GET","htu":"https://ex.com/a","ath":ath_padded});
        let jws_pad = make_jws(&sk, h.clone(), p_pad);
        let mut store3 = MemoryStore::default();
        let err = verify_proof(
            &mut store3,
            &jws_pad,
            "https://ex.com/a",
            "GET",
            Some(at),
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::AthMalformed);
    }

    #[tokio::test]
    async fn freshness_future_skew_and_stale() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});

        // Future skew just over limit
        let p_future =
            serde_json::json!({"jti":"jf","iat":now + 6,"htm":"GET","htu":"https://ex.com/a"});
        let jws_future = make_jws(&sk, h.clone(), p_future);
        let mut store1 = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_secs: 300,
            future_skew_secs: 5,
        };
        let err = verify_proof(
            &mut store1,
            &jws_future,
            "https://ex.com/a",
            "GET",
            None,
            opts,
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::FutureSkew);

        // Stale just over limit
        let p_stale =
            serde_json::json!({"jti":"js","iat":now - 301,"htm":"GET","htu":"https://ex.com/a"});
        let jws_stale = make_jws(&sk, h.clone(), p_stale);
        let mut store2 = MemoryStore::default();
        let opts = VerifyOptions {
            max_age_secs: 300,
            future_skew_secs: 5,
        };
        let err = verify_proof(
            &mut store2,
            &jws_stale,
            "https://ex.com/a",
            "GET",
            None,
            opts,
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::Stale);
    }

    #[tokio::test]
    async fn replay_same_jti_is_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"jr","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let ok1 = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await;
        assert!(ok1.is_ok());
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::Replay);
    }

    #[tokio::test]
    async fn signature_tamper_detected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"jt","iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let mut jws = make_jws(&sk, h, p);

        // Flip one byte in the payload section (keep base64url valid length)
        let bytes = unsafe { jws.as_bytes_mut() }; // alternative: rebuild string
        // Find the second '.' and flip a safe ASCII char before it
        let mut dot_count = 0usize;
        for i in 0..bytes.len() {
            if bytes[i] == b'.' {
                dot_count += 1;
                if dot_count == 2 && i > 10 {
                    bytes[i - 5] ^= 0x01; // tiny flip
                    break;
                }
            }
        }

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::InvalidSignature);
    }

    #[tokio::test]
    async fn method_mismatch_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":"jm","iat":now,"htm":"POST","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::HtmMismatch);
    }

    #[test]
    fn normalize_helpers_examples() {
        // sanity checks for helpers used by verify_proof
        assert_eq!(
            normalize_htu("https://EX.com:443/a/./b/../c?x=1#frag").unwrap(),
            "https://ex.com/a/c"
        );
        assert_eq!(normalize_method("get").unwrap(), "GET");
        assert!(normalize_method("CUSTOM").is_err());
    }

    #[tokio::test]
    async fn jti_too_long_rejected() {
        let (sk, x, y) = gen_es256_key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let too_long = "x".repeat(513);
        let h = serde_json::json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}});
        let p = serde_json::json!({"jti":too_long,"iat":now,"htm":"GET","htu":"https://ex.com/a"});
        let jws = make_jws(&sk, h, p);

        let mut store = MemoryStore::default();
        let err = verify_proof(
            &mut store,
            &jws,
            "https://ex.com/a",
            "GET",
            None,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        matches!(err, DpopError::JtiTooLong);
    }
}
