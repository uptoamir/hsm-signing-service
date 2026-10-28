//! Key backend abstraction.
//!
//! The HTTP layer only ever talks to `dyn KeyBackend`. Two implementations
//! exist: [`pkcs11::Pkcs11Backend`] (real token via PKCS#11, used in
//! production and in the integration test against SoftHSM2) and
//! [`mock::MockBackend`] (in-memory software keys, used by unit tests and for
//! running the API without a token).
//!
//! Signatures returned by [`KeyBackend::sign`] are in the *raw* form produced
//! by the primitive (ECDSA: `r || s`, RSA-PSS: PKCS#1 block, Ed25519: 64
//! bytes). Encoding choices such as DER for ECDSA are the API layer's concern.

pub mod mock;
pub mod pkcs11;
pub mod pool;

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::HsmError;

/// Signing algorithms exposed by the API. The serialized names are the
/// wire-format identifiers used in requests and responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// ECDSA over P-256; the service pre-hashes the payload with SHA-256.
    #[serde(rename = "ECDSA_P256_SHA256")]
    EcdsaP256Sha256,
    /// RSASSA-PSS with SHA-256 / MGF1-SHA-256 / 32-byte salt; pre-hashed.
    #[serde(rename = "RSA_PSS_SHA256")]
    RsaPssSha256,
    /// Pure Ed25519 (RFC 8032); the whole payload is passed to the token.
    #[serde(rename = "ED25519")]
    Ed25519,
}

impl SigningAlgorithm {
    pub const ALL: [SigningAlgorithm; 3] = [
        SigningAlgorithm::EcdsaP256Sha256,
        SigningAlgorithm::RsaPssSha256,
        SigningAlgorithm::Ed25519,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
            Self::RsaPssSha256 => "RSA_PSS_SHA256",
            Self::Ed25519 => "ED25519",
        }
    }

    /// The key kind this algorithm requires.
    pub fn key_kind(self) -> KeyKind {
        match self {
            Self::EcdsaP256Sha256 => KeyKind::EcdsaP256,
            Self::RsaPssSha256 => KeyKind::Rsa3072,
            Self::Ed25519 => KeyKind::Ed25519,
        }
    }

    /// Whether the service hashes the payload before handing it to the token.
    /// Ed25519 is a "pure" scheme and must see the whole message.
    pub fn prehash(self) -> bool {
        !matches!(self, Self::Ed25519)
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SigningAlgorithm {
    type Err = HsmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .iter()
            .copied()
            .find(|a| a.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| HsmError::UnsupportedAlgorithm(s.to_string()))
    }
}

/// The kinds of keys the service knows how to provision and use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyKind {
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    #[serde(rename = "rsa-3072")]
    Rsa3072,
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "aes-256")]
    Aes256,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Rsa3072 => "rsa-3072",
            Self::Ed25519 => "ed25519",
            Self::Aes256 => "aes-256",
        }
    }

    pub fn is_symmetric(self) -> bool {
        matches!(self, Self::Aes256)
    }

    /// Signing algorithms usable with this key kind.
    pub fn algorithms(self) -> &'static [SigningAlgorithm] {
        match self {
            Self::EcdsaP256 => &[SigningAlgorithm::EcdsaP256Sha256],
            Self::Rsa3072 => &[SigningAlgorithm::RsaPssSha256],
            Self::Ed25519 => &[SigningAlgorithm::Ed25519],
            Self::Aes256 => &[],
        }
    }
}

impl fmt::Display for KeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata about a key, read back from the token's attributes. The
/// `extractable`/`sensitive` flags are what prove that key material cannot
/// leave the cryptographic boundary.
#[derive(Debug, Clone, Serialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub kind: KeyKind,
    pub algorithms: Vec<SigningAlgorithm>,
    /// `CKA_SENSITIVE`: the key value cannot be read with `C_GetAttributeValue`.
    pub sensitive: bool,
    /// `CKA_EXTRACTABLE`: whether the key may be wrapped out of the token.
    pub extractable: bool,
    /// `CKA_NEVER_EXTRACTABLE`: the key has never been extractable since creation.
    pub never_extractable: bool,
    /// `CKA_LOCAL`: the key was generated inside the token (not imported).
    pub local: bool,
    /// `CKA_TOKEN`: persistent token object (as opposed to a session object).
    pub token_object: bool,
}

/// A public key exported from the token. Public keys are, by definition, safe
/// to leave the boundary; the `Debug` impl still only prints the kind.
#[derive(Clone)]
pub enum PublicKey {
    /// SEC1 uncompressed point (`0x04 || X || Y`, 65 bytes).
    EcdsaP256 { sec1: Vec<u8> },
    /// Big-endian modulus and public exponent.
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// 32-byte compressed Edwards point.
    Ed25519 { bytes: [u8; 32] },
}

impl PublicKey {
    pub fn kind(&self) -> KeyKind {
        match self {
            Self::EcdsaP256 { .. } => KeyKind::EcdsaP256,
            Self::Rsa { .. } => KeyKind::Rsa3072,
            Self::Ed25519 { .. } => KeyKind::Ed25519,
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.kind())
    }
}

/// AES-GCM output: the IV generated by the token and `ciphertext || tag`.
#[derive(Debug, Clone)]
pub struct Ciphertext {
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
}

/// Declarative description of a key the service must have available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySpec {
    /// Stable identifier; stored as both `CKA_LABEL` and `CKA_ID` on the token.
    pub id: String,
    pub kind: KeyKind,
    /// If true, failure to provision this key (for example because the token
    /// lacks the mechanism) is logged and skipped instead of aborting startup.
    #[serde(default)]
    pub optional: bool,
}

/// Contents of `keys.yaml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeysConfig {
    pub keys: Vec<KeySpec>,
}

impl KeysConfig {
    /// Loads the key list from a YAML file, or returns the built-in default set
    /// when the file does not exist.
    pub fn load_or_default(path: &Path) -> anyhow::Result<Self> {
        let cfg = if path.exists() {
            let text = std::fs::read_to_string(path)?;
            serde_yaml_ng::from_str::<Self>(&text)?
        } else {
            tracing::warn!(path = %path.display(), "keys config not found; using built-in defaults");
            Self::builtin_default()
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn builtin_default() -> Self {
        Self {
            keys: vec![
                KeySpec {
                    id: "arkion-intermediate-prod".into(),
                    kind: KeyKind::EcdsaP256,
                    optional: false,
                },
                KeySpec {
                    id: "arkion-kek-prod".into(),
                    kind: KeyKind::Aes256,
                    optional: false,
                },
            ],
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let mut seen = std::collections::HashSet::new();
        for k in &self.keys {
            validate_key_id(&k.id)
                .map_err(|e| anyhow::anyhow!("invalid key id {:?}: {e}", k.id))?;
            if !seen.insert(k.id.as_str()) {
                anyhow::bail!("duplicate key id {:?}", k.id);
            }
        }
        Ok(())
    }
}

/// Key identifiers double as PKCS#11 labels, so keep them short and plain.
pub fn validate_key_id(id: &str) -> Result<(), HsmError> {
    if id.is_empty() || id.len() > 64 {
        return Err(HsmError::InvalidInput(
            "key_id must be 1..=64 characters".into(),
        ));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(HsmError::InvalidInput(
            "key_id may only contain ASCII letters, digits, '-', '_' and '.'".into(),
        ));
    }
    Ok(())
}

/// Result of exercising the wrap/unwrap workflow (see
/// [`KeyBackend::wrap_roundtrip`]). Besides the positive round trip it records
/// the token's answers to two deliberately illegal requests, which is the
/// closest thing to a proof that the KEK is non-exportable.
#[derive(Debug, Clone, Serialize)]
pub struct WrapRoundtrip {
    pub kek_id: String,
    pub wrap_mechanism: &'static str,
    pub wrapped_key_len: usize,
    /// Data encrypted under the original DEK decrypted correctly under the
    /// unwrapped copy.
    pub roundtrip_ok: bool,
    /// Outcome of asking the token to wrap the non-extractable KEK itself.
    pub kek_wrap_attempt: String,
    /// Outcome of asking the token for the KEK's `CKA_VALUE`.
    pub kek_value_read_attempt: String,
}

/// Snapshot of the session pool, for metrics and readiness.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct PoolStats {
    pub capacity: usize,
    pub in_use: usize,
    pub idle: usize,
    pub waiters: usize,
    pub sessions_opened: u64,
    pub sessions_recycled: u64,
    pub acquire_timeouts: u64,
}

/// The cryptographic boundary as seen by the rest of the service.
///
/// Implementations must guarantee that private and secret key material is
/// never returned, serialized or logged by any of these methods.
#[async_trait]
pub trait KeyBackend: Send + Sync {
    /// Short name used in logs and `/readyz`.
    fn name(&self) -> &'static str;

    /// Ensures every key in `specs` exists (generating it inside the boundary
    /// if absent) and registers it for use. Returns metadata for each key.
    async fn provision(&self, specs: &[KeySpec]) -> Result<Vec<KeyInfo>, HsmError>;

    /// Signs `payload` with the named key. Returns the raw signature.
    async fn sign(
        &self,
        key_id: &str,
        algorithm: SigningAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Exports the public half of an asymmetric key.
    async fn public_key(&self, key_id: &str) -> Result<PublicKey, HsmError>;

    /// AES-256-GCM encryption inside the boundary with a token-generated IV.
    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, HsmError>;

    /// AES-256-GCM decryption inside the boundary. Fails with
    /// [`HsmError::DecryptFailed`] when the tag does not verify.
    async fn decrypt(
        &self,
        key_id: &str,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HsmError>;

    /// Metadata for every registered key, read from the token.
    async fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError>;

    /// Exercises key wrapping under the named KEK (see [`WrapRoundtrip`]).
    async fn wrap_roundtrip(&self, kek_id: &str) -> Result<WrapRoundtrip, HsmError>;

    /// Cheap liveness probe against the boundary.
    async fn health(&self) -> Result<(), HsmError>;

    fn pool_stats(&self) -> PoolStats;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_kind_names_match_wire_format() {
        for kind in [
            KeyKind::EcdsaP256,
            KeyKind::Rsa3072,
            KeyKind::Ed25519,
            KeyKind::Aes256,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            assert_eq!(serde_json::from_str::<KeyKind>(&json).unwrap(), kind);
        }
        for alg in SigningAlgorithm::ALL {
            let json = serde_json::to_string(&alg).unwrap();
            assert_eq!(json, format!("\"{}\"", alg.as_str()));
            assert_eq!(alg.as_str().parse::<SigningAlgorithm>().unwrap(), alg);
        }
    }

    #[test]
    fn keys_yaml_in_repo_parses() {
        let cfg = KeysConfig::load_or_default(std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/keys.yaml"
        )))
        .unwrap();
        assert!(cfg.keys.iter().any(|k| k.kind == KeyKind::Aes256));
        assert!(cfg.keys.iter().any(|k| k.kind == KeyKind::EcdsaP256));
    }

    #[test]
    fn key_id_validation() {
        assert!(validate_key_id("arkion-intermediate-prod").is_ok());
        assert!(validate_key_id("a.b_c-1").is_ok());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("../x").is_err());
        assert!(validate_key_id("with space").is_err());
        assert!(validate_key_id(&"x".repeat(65)).is_err());
    }
}
