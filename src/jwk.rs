use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::VerifyingKey;
use p256::{EncodedPoint, FieldBytes};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::DpopError;

/// Build a P-256 verifying key from JWK x/y (base64url, no padding).
pub fn verifying_key_from_p256_xy(x_b64: &str, y_b64: &str) -> Result<VerifyingKey, DpopError> {
    let x = B64
        .decode(x_b64)
        .map_err(|_| DpopError::BadJwk("bad jwk.x"))?;
    let y = B64
        .decode(y_b64)
        .map_err(|_| DpopError::BadJwk("bad jwk.y"))?;

    if x.len() != 32 || y.len() != 32 {
        return Err(DpopError::BadJwk("jwk x/y must be 32 bytes"));
    }

    let point = EncodedPoint::from_affine_coordinates(
        FieldBytes::from_slice(&x),
        FieldBytes::from_slice(&y),
        /* compress = */ false,
    );

    VerifyingKey::from_encoded_point(&point).map_err(|_| DpopError::BadJwk("invalid EC point"))
}

pub fn thumbprint_ec_p256(x_b64: &str, y_b64: &str) -> Result<String, DpopError> {
    let mut m = BTreeMap::new();
    m.insert("crv", "P-256");
    m.insert("kty", "EC");
    m.insert("x", x_b64);
    m.insert("y", y_b64);
    let canonical = serde_json::to_string(&m).map_err(|_| DpopError::BadJwk("canonicalize"))?;
    Ok(B64.encode(Sha256::digest(canonical.as_bytes())))
}
