//! In-memory software backend.
//!
//! Used by unit tests and for running the API without a token
//! (`--backend mock`). It mirrors the PKCS#11 backend's observable behaviour
//! (raw signature formats, IV handling, bounded concurrency with an optional
//! simulated latency) but keeps keys in process memory, so it must never be
//! used where real key protection is required.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use rsa::traits::PublicKeyParts;
use rsa::{Pss, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::crypto::sha256;
use crate::error::HsmError;
use crate::hsm::{
    Ciphertext, KeyBackend, KeyInfo, KeyKind, KeySpec, PoolStats, PublicKey, SigningAlgorithm,
    WrapRoundtrip,
};

enum MockKey {
    EcdsaP256(p256::ecdsa::SigningKey),
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::SigningKey),
    Aes256(Zeroizing<[u8; 32]>),
}

impl MockKey {
    fn kind(&self) -> KeyKind {
        match self {
            Self::EcdsaP256(_) => KeyKind::EcdsaP256,
            Self::Rsa(_) => KeyKind::Rsa3072,
            Self::Ed25519(_) => KeyKind::Ed25519,
            Self::Aes256(_) => KeyKind::Aes256,
        }
    }

    fn generate(kind: KeyKind) -> Result<Self, HsmError> {
        Ok(match kind {
            KeyKind::EcdsaP256 => Self::EcdsaP256(p256::ecdsa::SigningKey::random(&mut OsRng)),
            // 2048 bits keeps test start-up fast; the PKCS#11 backend uses 3072.
            KeyKind::Rsa3072 => Self::Rsa(
                RsaPrivateKey::new(&mut OsRng, 2048)
                    .map_err(|e| HsmError::Internal(format!("mock RSA keygen failed: {e}")))?,
            ),
            KeyKind::Ed25519 => Self::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng)),
            KeyKind::Aes256 => {
                let mut k = Zeroizing::new([0u8; 32]);
                OsRng.fill_bytes(k.as_mut());
                Self::Aes256(k)
            }
        })
    }
}

pub struct MockBackend {
    keys: RwLock<HashMap<String, MockKey>>,
    latency: Duration,
    permits: Arc<Semaphore>,
    capacity: usize,
    acquire_timeout: Duration,
    in_use: AtomicUsize,
    waiters: AtomicUsize,
    acquire_timeouts: AtomicU64,
    ops: AtomicU64,
}

impl MockBackend {
    /// `latency` is added to every operation while a permit is held, to
    /// imitate a token with `capacity` sessions.
    pub fn new(latency: Duration, capacity: usize, acquire_timeout: Duration) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            latency,
            permits: Arc::new(Semaphore::new(capacity.max(1))),
            capacity: capacity.max(1),
            acquire_timeout,
            in_use: AtomicUsize::new(0),
            waiters: AtomicUsize::new(0),
            acquire_timeouts: AtomicU64::new(0),
            ops: AtomicU64::new(0),
        }
    }

    async fn slot(&self) -> Result<OwnedSemaphorePermit, HsmError> {
        self.waiters.fetch_add(1, Ordering::Relaxed);
        let acquired = tokio::time::timeout(
            self.acquire_timeout,
            Arc::clone(&self.permits).acquire_owned(),
        )
        .await;
        self.waiters.fetch_sub(1, Ordering::Relaxed);
        let permit = match acquired {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(HsmError::Unavailable("mock pool closed".into())),
            Err(_) => {
                self.acquire_timeouts.fetch_add(1, Ordering::Relaxed);
                return Err(HsmError::Busy(self.acquire_timeout));
            }
        };
        self.in_use.fetch_add(1, Ordering::Relaxed);
        if !self.latency.is_zero() {
            tokio::time::sleep(self.latency).await;
        }
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.ops.fetch_add(1, Ordering::Relaxed);
        Ok(permit)
    }

    fn info(key_id: &str, kind: KeyKind) -> KeyInfo {
        KeyInfo {
            key_id: key_id.to_string(),
            kind,
            algorithms: kind.algorithms().to_vec(),
            sensitive: true,
            extractable: false,
            never_extractable: true,
            local: true,
            token_object: false,
        }
    }

    fn sign_sync(
        &self,
        key_id: &str,
        algorithm: SigningAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let keys = self.keys.read();
        let key = keys
            .get(key_id)
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))?;
        match (key, algorithm) {
            (MockKey::EcdsaP256(sk), SigningAlgorithm::EcdsaP256Sha256) => {
                let sig: p256::ecdsa::Signature = sk
                    .sign_prehash(&sha256(payload))
                    .map_err(|e| HsmError::Internal(format!("mock ECDSA failed: {e}")))?;
                Ok(sig.to_bytes().to_vec())
            }
            (MockKey::Rsa(sk), SigningAlgorithm::RsaPssSha256) => sk
                .sign_with_rng(
                    &mut OsRng,
                    Pss::new_with_salt::<Sha256>(32),
                    &sha256(payload),
                )
                .map_err(|e| HsmError::Internal(format!("mock RSA-PSS failed: {e}"))),
            (MockKey::Ed25519(sk), SigningAlgorithm::Ed25519) => {
                Ok(sk.sign(payload).to_bytes().to_vec())
            }
            (key, algorithm) => Err(HsmError::AlgorithmMismatch {
                key_id: key_id.to_string(),
                algorithm: algorithm.to_string(),
                kind: key.kind().to_string(),
            }),
        }
    }

    fn aes_key(&self, key_id: &str) -> Result<Zeroizing<[u8; 32]>, HsmError> {
        let keys = self.keys.read();
        match keys.get(key_id) {
            Some(MockKey::Aes256(k)) => Ok(k.clone()),
            Some(other) => Err(HsmError::AlgorithmMismatch {
                key_id: key_id.to_string(),
                algorithm: "AES_256_GCM".into(),
                kind: other.kind().to_string(),
            }),
            None => Err(HsmError::KeyNotFound(key_id.to_string())),
        }
    }
}

fn gcm_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext, HsmError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| HsmError::Internal(e.to_string()))?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let data = cipher
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| HsmError::Internal("mock AES-GCM encrypt failed".into()))?;
    Ok(Ciphertext {
        iv: iv.to_vec(),
        data,
    })
}

fn gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HsmError> {
    let iv: [u8; 12] = iv
        .try_into()
        .map_err(|_| HsmError::InvalidInput("iv must be 12 bytes".into()))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| HsmError::Internal(e.to_string()))?;
    cipher
        .decrypt(
            &Nonce::from(iv),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| HsmError::DecryptFailed)
}

#[async_trait]
impl KeyBackend for MockBackend {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn provision(&self, specs: &[KeySpec]) -> Result<Vec<KeyInfo>, HsmError> {
        let mut out = Vec::with_capacity(specs.len());
        for spec in specs {
            let exists = self.keys.read().contains_key(&spec.id);
            if !exists {
                let key = MockKey::generate(spec.kind)?;
                self.keys.write().insert(spec.id.clone(), key);
                tracing::info!(key_id = %spec.id, kind = %spec.kind, "generated mock key");
            }
            out.push(Self::info(&spec.id, spec.kind));
        }
        Ok(out)
    }

    async fn sign(
        &self,
        key_id: &str,
        algorithm: SigningAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let _permit = self.slot().await?;
        self.sign_sync(key_id, algorithm, payload)
    }

    async fn public_key(&self, key_id: &str) -> Result<PublicKey, HsmError> {
        let keys = self.keys.read();
        match keys.get(key_id) {
            Some(MockKey::EcdsaP256(sk)) => Ok(PublicKey::EcdsaP256 {
                sec1: sk
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
            }),
            Some(MockKey::Rsa(sk)) => {
                let pk = RsaPublicKey::from(sk);
                Ok(PublicKey::Rsa {
                    modulus: pk.n().to_bytes_be(),
                    exponent: pk.e().to_bytes_be(),
                })
            }
            Some(MockKey::Ed25519(sk)) => Ok(PublicKey::Ed25519 {
                bytes: sk.verifying_key().to_bytes(),
            }),
            Some(MockKey::Aes256(_)) => Err(HsmError::InvalidInput(format!(
                "key {key_id} is symmetric and has no public key"
            ))),
            None => Err(HsmError::KeyNotFound(key_id.to_string())),
        }
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, HsmError> {
        let _permit = self.slot().await?;
        let key = self.aes_key(key_id)?;
        gcm_encrypt(&key, plaintext, aad)
    }

    async fn decrypt(
        &self,
        key_id: &str,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        let _permit = self.slot().await?;
        let key = self.aes_key(key_id)?;
        gcm_decrypt(&key, iv, ciphertext, aad)
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError> {
        let keys = self.keys.read();
        let mut out: Vec<KeyInfo> = keys
            .iter()
            .map(|(id, k)| Self::info(id, k.kind()))
            .collect();
        out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        Ok(out)
    }

    async fn wrap_roundtrip(&self, kek_id: &str) -> Result<WrapRoundtrip, HsmError> {
        let _permit = self.slot().await?;
        let kek = self.aes_key(kek_id)?;
        // Ephemeral DEK, used once, then "wrapped" (AES-GCM stands in for
        // AES-KW here), discarded, unwrapped and used again.
        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(dek.as_mut());
        let sample = b"wrap-roundtrip sample";
        let ct = gcm_encrypt(&dek, sample, b"")?;
        let wrapped = gcm_encrypt(&kek, dek.as_ref(), b"dek")?;
        drop(dek);
        let unwrapped = gcm_decrypt(&kek, &wrapped.iv, &wrapped.data, b"dek")?;
        let unwrapped: [u8; 32] = unwrapped
            .as_slice()
            .try_into()
            .map_err(|_| HsmError::Internal("unwrapped DEK has wrong length".into()))?;
        let roundtrip_ok = gcm_decrypt(&unwrapped, &ct.iv, &ct.data, b"")? == sample;
        Ok(WrapRoundtrip {
            kek_id: kek_id.to_string(),
            wrap_mechanism: "mock (AES-GCM stand-in for CKM_AES_KEY_WRAP_PAD)",
            wrapped_key_len: wrapped.iv.len() + wrapped.data.len(),
            roundtrip_ok,
            kek_wrap_attempt: "rejected: mock keys are never extractable".into(),
            kek_value_read_attempt: "rejected: mock keys are sensitive".into(),
        })
    }

    async fn health(&self) -> Result<(), HsmError> {
        Ok(())
    }

    fn pool_stats(&self) -> PoolStats {
        PoolStats {
            capacity: self.capacity,
            in_use: self.in_use.load(Ordering::Relaxed),
            idle: self.permits.available_permits(),
            waiters: self.waiters.load(Ordering::Relaxed),
            sessions_opened: self.capacity as u64,
            sessions_recycled: 0,
            acquire_timeouts: self.acquire_timeouts.load(Ordering::Relaxed),
        }
    }
}
