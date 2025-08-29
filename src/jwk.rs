use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::DecodingKey;
use p256::pkcs8::EncodePublicKey;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::DpopError;

pub fn decoding_key_from_p256_xy(x_b64: &str, y_b64: &str) -> Result<DecodingKey, DpopError> {
    let x = B64
        .decode(x_b64.as_bytes())
        .map_err(|_| DpopError::BadJwk("bad x"))?;
    let y = B64
        .decode(y_b64.as_bytes())
        .map_err(|_| DpopError::BadJwk("bad y"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(DpopError::BadJwk("x/y must be 32 bytes"));
    }

    // x,y are 32-byte slices decoded from base64url
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&x);
    sec1[33..65].copy_from_slice(&y);

    let pk = p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| DpopError::BadJwk("invalid EC point"))?;

    let spki = pk
        .to_public_key_der()
        .map_err(|_| DpopError::BadJwk("SPKI encode failed"))?;
    Ok(jsonwebtoken::DecodingKey::from_ec_der(spki.as_bytes()))
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
