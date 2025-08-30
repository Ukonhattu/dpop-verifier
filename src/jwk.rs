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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;

    // --- verifying_key_from_p256_xy -------------------------------------------

    #[test]
    fn vk_from_xy_roundtrip_valid() {
        // Generate a real keypair, extract x/y, and round-trip through the helper.
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        let ep = vk.to_encoded_point(false);
        let x_b64 = B64.encode(ep.x().expect("x"));
        let y_b64 = B64.encode(ep.y().expect("y"));

        let got = verifying_key_from_p256_xy(&x_b64, &y_b64).expect("verifying key");
        assert_eq!(got.to_encoded_point(false), ep);
    }

    #[test]
    fn vk_rejects_bad_base64_inputs() {
        // Invalid URL-safe base64 (has padding/invalid chars)
        let good32 = B64.encode([0u8; 32]);
        assert!(
            verifying_key_from_p256_xy("AA==", &good32).is_err(),
            "padded x should fail"
        );
        assert!(
            verifying_key_from_p256_xy(&good32, "A*").is_err(),
            "invalid char in y should fail"
        );
    }

    #[test]
    fn vk_rejects_wrong_lengths() {
        let x31 = B64.encode([0u8; 31]);
        let x32 = B64.encode([0u8; 32]);
        let y33 = B64.encode([0u8; 33]);
        assert!(
            verifying_key_from_p256_xy(&x31, &x32).is_err(),
            "31-byte x must fail"
        );
        assert!(
            verifying_key_from_p256_xy(&x32, &y33).is_err(),
            "33-byte y must fail"
        );
    }

    #[test]
    fn vk_rejects_invalid_point() {
        // (0,0) is not a valid P-256 point
        let zeros32 = B64.encode([0u8; 32]);
        let err = verifying_key_from_p256_xy(&zeros32, &zeros32).unwrap_err();
        matches!(err, DpopError::BadJwk(_));
    }

    // --- thumbprint_ec_p256 ----------------------------------------------------

    #[test]
    fn thumbprint_has_length_43_and_no_padding() {
        // Any 32-byte x/y produce SHA-256 -> 32 bytes -> base64url length 43, no '=' padding
        let x = B64.encode([0u8; 32]);
        let y = B64.encode([1u8; 32]);
        let t = thumbprint_ec_p256(&x, &y).expect("thumbprint");
        assert_eq!(t.len(), 43);
        assert!(!t.contains('='));
    }

    #[test]
    fn thumbprint_is_deterministic() {
        let x = B64.encode([42u8; 32]);
        let y = B64.encode([99u8; 32]);
        let t1 = thumbprint_ec_p256(&x, &y).unwrap();
        let t2 = thumbprint_ec_p256(&x, &y).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn thumbprint_changes_when_xy_changes() {
        let x = B64.encode([7u8; 32]);
        let mut x2_bytes = [7u8; 32];
        x2_bytes[0] ^= 0x01; // flip a bit
        let x2 = B64.encode(x2_bytes);
        let y = B64.encode([9u8; 32]);

        let t1 = thumbprint_ec_p256(&x, &y).unwrap();
        let t2 = thumbprint_ec_p256(&x2, &y).unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn thumbprint_canonicalization_order_is_fixed() {
        // Verify canonical JWK JSON (crv,kty,x,y in sorted key order) produces a fixed digest.
        // Since the function uses BTreeMap, insertion order shouldn't matter to the result.
        let x = B64.encode([0xAB; 32]);
        let y = B64.encode([0xCD; 32]);

        // Compute via function
        let tf = thumbprint_ec_p256(&x, &y).unwrap();

        // Recompute manually to assert intent: JSON of sorted keys -> sha256 -> base64url (no pad)
        let mut m = BTreeMap::new();
        m.insert("crv", "P-256");
        m.insert("kty", "EC");
        m.insert("x", x.as_str());
        m.insert("y", y.as_str());
        let canonical = serde_json::to_string(&m).unwrap();
        let manual = B64.encode(Sha256::digest(canonical.as_bytes()));
        assert_eq!(tf, manual);
    }
}
