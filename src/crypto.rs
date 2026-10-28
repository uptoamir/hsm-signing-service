//! Software-side cryptography.
//!
//! Everything here operates on *public* material only: digests of payloads,
//! public keys exported from the token, and signatures produced by it. No
//! private or secret key ever passes through this module.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{BigUint, Pss, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::error::HsmError;
use crate::hsm::{PublicKey, SigningAlgorithm};

/// DER encoding of the `prime256v1` OID (1.2.840.10045.3.1.7), the value of
/// `CKA_EC_PARAMS` for a P-256 key.
pub const P256_OID_DER: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// DER encoding of the Ed25519 OID (1.3.101.112), the value of
/// `CKA_EC_PARAMS` for an Edwards key.
pub const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// Length of an uncompressed SEC1 P-256 point.
pub const P256_POINT_LEN: usize = 65;
/// Length of an Ed25519 public key.
pub const ED25519_POINT_LEN: usize = 32;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Extracts the point from a `CKA_EC_POINT` attribute value.
///
/// PKCS#11 specifies a DER `OCTET STRING` wrapper (`0x04 <len> <point>`);
/// some tokens return the bare point. The expected length disambiguates the
/// two, because an uncompressed point also starts with `0x04`.
pub fn ec_point_contents(attr: &[u8], expected_len: usize) -> Result<&[u8], HsmError> {
    if attr.len() == expected_len + 2 && attr[0] == 0x04 && attr[1] as usize == expected_len {
        return Ok(&attr[2..]);
    }
    if attr.len() == expected_len {
        return Ok(attr);
    }
    Err(HsmError::Internal(format!(
        "unexpected CKA_EC_POINT encoding ({} bytes, expected {})",
        attr.len(),
        expected_len
    )))
}

/// Converts a raw `r || s` ECDSA signature (what PKCS#11 returns) to the
/// ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` form used by X.509 and TLS.
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, HsmError> {
    let sig = EcdsaSignature::from_slice(raw)
        .map_err(|_| HsmError::Internal("token returned a malformed ECDSA signature".into()))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Converts a DER-encoded ECDSA signature back to raw `r || s`.
pub fn ecdsa_der_to_raw(der: &[u8]) -> Result<Vec<u8>, HsmError> {
    let sig = EcdsaSignature::from_der(der).map_err(|_| {
        HsmError::InvalidInput("signature is not a DER-encoded ECDSA signature".into())
    })?;
    Ok(sig.to_bytes().to_vec())
}

/// Verifies a raw signature over `payload` with an exported public key.
///
/// Returns `Ok(false)` for a well-formed but invalid signature and an error
/// only when the inputs are structurally unusable (wrong key kind, corrupt
/// public key).
pub fn verify(
    public: &PublicKey,
    algorithm: SigningAlgorithm,
    payload: &[u8],
    signature: &[u8],
) -> Result<bool, HsmError> {
    match (public, algorithm) {
        (PublicKey::EcdsaP256 { sec1 }, SigningAlgorithm::EcdsaP256Sha256) => {
            let vk = EcdsaVerifyingKey::from_sec1_bytes(sec1)
                .map_err(|e| HsmError::Internal(format!("invalid P-256 public key: {e}")))?;
            let Ok(sig) = EcdsaSignature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(vk.verify_prehash(&sha256(payload), &sig).is_ok())
        }
        (PublicKey::Rsa { modulus, exponent }, SigningAlgorithm::RsaPssSha256) => {
            let pk = RsaPublicKey::new(
                BigUint::from_bytes_be(modulus),
                BigUint::from_bytes_be(exponent),
            )
            .map_err(|e| HsmError::Internal(format!("invalid RSA public key: {e}")))?;
            Ok(pk
                .verify(
                    Pss::new_with_salt::<Sha256>(32),
                    &sha256(payload),
                    signature,
                )
                .is_ok())
        }
        (PublicKey::Ed25519 { bytes }, SigningAlgorithm::Ed25519) => {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|e| HsmError::Internal(format!("invalid Ed25519 public key: {e}")))?;
            let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(vk.verify_strict(payload, &sig).is_ok())
        }
        (pk, alg) => Err(HsmError::InvalidInput(format!(
            "algorithm {alg} cannot verify with a {} key",
            pk.kind()
        ))),
    }
}

/// Encodes a public key as a PEM `SubjectPublicKeyInfo` block, so clients can
/// verify signatures with standard tooling (`openssl pkeyutl`, etc.).
pub fn public_key_pem(public: &PublicKey) -> Result<String, HsmError> {
    let enc =
        |e: &dyn std::fmt::Display| HsmError::Internal(format!("cannot encode public key: {e}"));
    match public {
        PublicKey::EcdsaP256 { sec1 } => p256::PublicKey::from_sec1_bytes(sec1)
            .map_err(|e| enc(&e))?
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| enc(&e)),
        PublicKey::Rsa { modulus, exponent } => RsaPublicKey::new(
            BigUint::from_bytes_be(modulus),
            BigUint::from_bytes_be(exponent),
        )
        .map_err(|e| enc(&e))?
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| enc(&e)),
        PublicKey::Ed25519 { bytes } => ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|e| enc(&e))?
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| enc(&e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_point_accepts_wrapped_and_bare() {
        let point = [0x04u8; 65];
        let mut wrapped = vec![0x04, 0x41];
        wrapped.extend_from_slice(&point);
        assert_eq!(ec_point_contents(&wrapped, 65).unwrap(), &point[..]);
        assert_eq!(ec_point_contents(&point, 65).unwrap(), &point[..]);
        assert!(ec_point_contents(&point[..64], 65).is_err());
    }

    #[test]
    fn ecdsa_der_roundtrip() {
        let mut raw = vec![0u8; 64];
        raw[0] = 1;
        raw[32] = 1;
        let der = ecdsa_raw_to_der(&raw).unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(ecdsa_der_to_raw(&der).unwrap(), raw);
        assert!(ecdsa_der_to_raw(&raw).is_err());
    }
}
