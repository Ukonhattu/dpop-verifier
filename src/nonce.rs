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
const RAND_LEN: usize = 16;
const MAC_LEN: usize = 16; // truncated

/// Optional binding context (only fields you want to bind).
pub struct NonceCtx<'a> {
    pub htu: Option<&'a str>,
    pub htm: Option<&'a str>,
    pub jkt: Option<&'a str>,
}

fn ctx_bytes(ctx: &NonceCtx<'_>) -> Vec<u8> {
    let mut v = Vec::new();
    if let Some(htu) = ctx.htu {
        v.extend_from_slice(b"HTU\0");
        v.extend_from_slice(htu.as_bytes());
        v.push(0);
    }
    if let Some(htm) = ctx.htm {
        v.extend_from_slice(b"HTM\0");
        v.extend_from_slice(htm.as_bytes());
        v.push(0);
    }
    if let Some(jkt) = ctx.jkt {
        v.extend_from_slice(b"JKT\0");
        v.extend_from_slice(jkt.as_bytes());
        v.push(0);
    }
    v
}

/// Issue a fresh nonce bound to the given context.
pub fn issue_nonce(secret: &[u8], now_unix: i64, ctx: &NonceCtx<'_>) -> String {
    let ver = [NONCE_VERSION];
    let ts = now_unix.to_be_bytes();

    let mut rand = [0u8; RAND_LEN];
    OsRng.fill_bytes(&mut rand);

    // MAC over (ver || ts || rand || ctx)
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(&ver);
    mac.update(&ts);
    mac.update(&rand);
    mac.update(&ctx_bytes(ctx));
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(1 + 8 + RAND_LEN + MAC_LEN);
    out.extend_from_slice(&ver);
    out.extend_from_slice(&ts);
    out.extend_from_slice(&rand);
    out.extend_from_slice(&tag[..MAC_LEN]);

    B64.encode(out)
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
    let raw = B64
        .decode(nonce_b64.as_bytes())
        .map_err(|_| DpopError::NonceMismatch)?;
    if raw.len() != 1 + 8 + RAND_LEN + MAC_LEN {
        return Err(DpopError::NonceMismatch);
    }

    let ver = raw[0];
    if ver != NONCE_VERSION {
        return Err(DpopError::NonceMismatch);
    }

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&raw[1..9]);
    let ts = i64::from_be_bytes(ts_bytes);

    let rand = &raw[9..9 + RAND_LEN];
    let mac_in = &raw[9 + RAND_LEN..];

    // Age & small future skew checks
    if now_unix - ts > max_age_secs {
        return Err(DpopError::NonceStale);
    }
    // allow small future skew (5s)
    if ts - now_unix > 5 {
        return Err(DpopError::FutureSkew);
    }

    // Recompute MAC
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(&[ver]);
    mac.update(&ts.to_be_bytes());
    mac.update(rand);
    mac.update(&ctx_bytes(ctx));
    let tag = mac.finalize().into_bytes();

    if bool::from(mac_in.ct_eq(&tag[..MAC_LEN])) {
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
    let mut last_err = DpopError::NonceMismatch;
    for s in secrets {
        match verify_nonce(s, nonce_b64, now_unix, max_age_secs, ctx) {
            Ok(()) => return Ok(()),
            Err(e @ DpopError::FutureSkew)
            | Err(e @ DpopError::NonceStale)
            | Err(e @ DpopError::NonceMismatch) => last_err = e,
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn roundtrip_ok_with_binding() {
        let secret = b"supersecretkey";
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ctx = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("POST"),
            jkt: Some("thumb"),
        };

        let n = issue_nonce(secret, now, &ctx);
        assert!(verify_nonce(secret, &n, now, 300, &ctx).is_ok());
    }

    #[test]
    fn bad_ctx_fails() {
        let secret = b"k";
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ctx1 = NonceCtx {
            htu: Some("https://ex.com/a"),
            htm: Some("GET"),
            jkt: Some("t"),
        };
        let n = issue_nonce(secret, now, &ctx1);

        // Change HTU → should fail
        let ctx2 = NonceCtx {
            htu: Some("https://ex.com/b"),
            htm: Some("GET"),
            jkt: Some("t"),
        };
        assert!(matches!(
            verify_nonce(secret, &n, now, 300, &ctx2),
            Err(DpopError::NonceMismatch)
        ));
    }

    #[test]
    fn stale_and_future_skew() {
        let secret = b"k2";
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ctx = NonceCtx {
            htu: None,
            htm: None,
            jkt: None,
        };

        let n_future = issue_nonce(secret, now + 10, &ctx);
        assert!(matches!(
            verify_nonce(secret, &n_future, now, 300, &ctx),
            Err(DpopError::FutureSkew)
        ));

        let n_old = issue_nonce(secret, now - 301, &ctx);
        assert!(matches!(
            verify_nonce(secret, &n_old, now, 300, &ctx),
            Err(DpopError::NonceStale)
        ));
    }

    #[test]
    fn rotation_any_secret() {
        let s1 = b"current";
        let s0 = b"previous";
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let ctx = NonceCtx {
            htu: Some("u"),
            htm: Some("M"),
            jkt: None,
        };

        let n0 = issue_nonce(s0, now, &ctx);
        assert!(
            verify_nonce_with_any(&[s1.as_slice(), s0.as_slice()], &n0, now, 300, &ctx).is_ok()
        );

        let n1 = issue_nonce(s1, now, &ctx);
        assert!(
            verify_nonce_with_any(&[s1.as_slice(), s0.as_slice()], &n1, now, 300, &ctx).is_ok()
        );
    }
}
