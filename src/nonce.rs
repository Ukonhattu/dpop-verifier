//! Stateless DPoP-Nonce issuance & verification using HMAC-SHA256.
//!
//! Nonce format (binary, then base64url(no-pad)):
//!   version(1) || ts_be(8) || rand(16) || mac(16)
//!
//! mac = HMAC-SHA256(secret, version || ts || rand || ctx_bytes)[..16]
//! ctx_bytes = concatenation of tagged optional fields:
//!   b"HTU\0" + htu + b"\0"  (if provided)
//!   b"HTM\0" + htm + b"\0"  (if provided)
//!   b"JKT\0" + jkt + b"\0"  (if provided)

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::DpopError;

type HmacSha256 = Hmac<Sha256>;

const NONCE_VERSION: u8 = 1;
const NONCE_RANDOM_LENGTH: usize = 16;
const NONCE_MAC_LENGTH: usize = 16; // truncated
const NONCE_TOTAL_LENGTH: usize = 1 + 8 + 16 + 16; // version + timestamp + random + mac
const NONCE_FUTURE_SKEW_SECS: i64 = 5;

/// Optional binding context (only fields you want to bind).
pub struct NonceCtx<'a> {
    pub htu: Option<&'a str>,
    pub htm: Option<&'a str>,
    pub jkt: Option<&'a str>,
}

fn ctx_bytes(ctx: &NonceCtx<'_>) -> Vec<u8> {
    let mut context_bytes = Vec::new();
    if let Some(htu) = ctx.htu {
        context_bytes.extend_from_slice(b"HTU\0");
        context_bytes.extend_from_slice(htu.as_bytes());
        context_bytes.push(0);
    }
    if let Some(htm) = ctx.htm {
        context_bytes.extend_from_slice(b"HTM\0");
        context_bytes.extend_from_slice(htm.as_bytes());
        context_bytes.push(0);
    }
    if let Some(jkt) = ctx.jkt {
        context_bytes.extend_from_slice(b"JKT\0");
        context_bytes.extend_from_slice(jkt.as_bytes());
        context_bytes.push(0);
    }
    context_bytes
}

/// Issue a fresh nonce bound to the given context.
/// 
/// # Panics
/// This function will panic if the HMAC secret is invalid (which should never happen
/// since HmacSha256 accepts keys of any length).
pub fn issue_nonce(secret: &[u8], now_unix: i64, ctx: &NonceCtx<'_>) -> String {
    let version_bytes = [NONCE_VERSION];
    let timestamp_bytes = now_unix.to_be_bytes();

    let mut random_bytes = [0u8; NONCE_RANDOM_LENGTH];
    OsRng.fill_bytes(&mut random_bytes);

    // MAC over (version || timestamp || random || context)
    // HMAC-SHA256 accepts keys of any length, so this should never fail
    let mut hmac = HmacSha256::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    hmac.update(&version_bytes);
    hmac.update(&timestamp_bytes);
    hmac.update(&random_bytes);
    hmac.update(&ctx_bytes(ctx));
    let mac_tag = hmac.finalize().into_bytes();

    let mut nonce_bytes = Vec::with_capacity(NONCE_TOTAL_LENGTH);
    nonce_bytes.extend_from_slice(&version_bytes);
    nonce_bytes.extend_from_slice(&timestamp_bytes);
    nonce_bytes.extend_from_slice(&random_bytes);
    nonce_bytes.extend_from_slice(&mac_tag[..NONCE_MAC_LENGTH]);

    B64.encode(nonce_bytes)
}

/// Verify a nonce with age & skew limits, re-binding to the given context.
/// On success returns Ok(()); on failure returns a DpopError (NonceMismatch/NonceStale/FutureSkew).
pub fn verify_nonce(
    secret: &[u8],
    nonce_b64: &str,
    now_unix: i64,
    max_age_secs: i64,
    ctx: &NonceCtx<'_>,
) -> Result<(), DpopError> {
    let nonce_bytes = B64
        .decode(nonce_b64.as_bytes())
        .map_err(|_| DpopError::NonceMismatch)?;
    
    if nonce_bytes.len() != NONCE_TOTAL_LENGTH {
        return Err(DpopError::NonceMismatch);
    }

    let version = nonce_bytes[0];
    if version != NONCE_VERSION {
        return Err(DpopError::NonceMismatch);
    }

    // Safe extraction of timestamp bytes
    let timestamp_bytes: [u8; 8] = nonce_bytes
        .get(1..9)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(DpopError::NonceMismatch)?;
    let timestamp = i64::from_be_bytes(timestamp_bytes);

    // Safe extraction of random and MAC bytes
    let random_bytes = nonce_bytes
        .get(9..9 + NONCE_RANDOM_LENGTH)
        .ok_or(DpopError::NonceMismatch)?;
    let mac_from_nonce = nonce_bytes
        .get(9 + NONCE_RANDOM_LENGTH..)
        .ok_or(DpopError::NonceMismatch)?;

    // Age & future skew checks
    if now_unix - timestamp > max_age_secs {
        return Err(DpopError::NonceStale);
    }
    if timestamp - now_unix > NONCE_FUTURE_SKEW_SECS {
        return Err(DpopError::FutureSkew);
    }

    // Recompute MAC
    // HMAC-SHA256 accepts keys of any length, so this should never fail
    let mut hmac = HmacSha256::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts keys of any length");
    hmac.update(&[version]);
    hmac.update(&timestamp.to_be_bytes());
    hmac.update(random_bytes);
    hmac.update(&ctx_bytes(ctx));
    let computed_mac = hmac.finalize().into_bytes();

    if bool::from(mac_from_nonce.ct_eq(&computed_mac[..NONCE_MAC_LENGTH])) {
        Ok(())
    } else {
        Err(DpopError::NonceMismatch)
    }
}

/// Verify against multiple secrets (e.g., key rotation: current, previous).
pub fn verify_nonce_with_any(
    secrets: &[&[u8]],
    nonce_b64: &str,
    now_unix: i64,
    max_age_secs: i64,
    ctx: &NonceCtx<'_>,
) -> Result<(), DpopError> {
    let mut last_error = DpopError::NonceMismatch;
    for secret in secrets {
        match verify_nonce(secret, nonce_b64, now_unix, max_age_secs, ctx) {
            Ok(()) => return Ok(()),
            Err(error @ DpopError::FutureSkew)
            | Err(error @ DpopError::NonceStale)
            | Err(error @ DpopError::NonceMismatch) => last_error = error,
            Err(error) => return Err(error),
        }
    }
    Err(last_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn roundtrip_ok_with_binding() {
        let secret = b"supersecretkey";
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let context = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("POST"),
            jkt: Some("thumb"),
        };

        let nonce = issue_nonce(secret, current_time, &context);
        assert!(verify_nonce(secret, &nonce, current_time, 300, &context).is_ok());
    }

    #[test]
    fn bad_ctx_fails() {
        let secret = b"k";
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let original_context = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("GET"),
            jkt: Some("t"),
        };
        let nonce = issue_nonce(secret, current_time, &original_context);

        // Change HTU → should fail
        let different_context = NonceCtx {
            htu: Some("https://ex.com/b"),
            htm: Some("GET"),
            jkt: Some("t"),
        };
        assert!(matches!(
            verify_nonce(secret, &nonce, current_time, 300, &different_context),
            Err(DpopError::NonceMismatch)
        ));
    }

    #[test]
    fn stale_and_future_skew() {
        let secret = b"k2";
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let empty_context = NonceCtx {
            htu: None,
            htm: None,
            jkt: None,
        };

        let future_nonce = issue_nonce(secret, current_time + 10, &empty_context);
        assert!(matches!(
            verify_nonce(secret, &future_nonce, current_time, 300, &empty_context),
            Err(DpopError::FutureSkew)
        ));

        let stale_nonce = issue_nonce(secret, current_time - 301, &empty_context);
        assert!(matches!(
            verify_nonce(secret, &stale_nonce, current_time, 300, &empty_context),
            Err(DpopError::NonceStale)
        ));
    }

    #[test]
    fn rotation_any_secret() {
        let current_secret = b"current";
        let previous_secret = b"previous";
        let current_time = OffsetDateTime::now_utc().unix_timestamp();
        let context = NonceCtx {
            htu: Some("u"),
            htm: Some("M"),
            jkt: None,
        };

        let nonce_from_previous = issue_nonce(previous_secret, current_time, &context);
        assert!(
            verify_nonce_with_any(&[current_secret.as_slice(), previous_secret.as_slice()], &nonce_from_previous, current_time, 300, &context).is_ok()
        );

        let nonce_from_current = issue_nonce(current_secret, current_time, &context);
        assert!(
            verify_nonce_with_any(&[current_secret.as_slice(), previous_secret.as_slice()], &nonce_from_current, current_time, 300, &context).is_ok()
        );
    }
}
