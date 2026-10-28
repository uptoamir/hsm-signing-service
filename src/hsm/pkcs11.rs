//! PKCS#11 backend.
//!
//! Keys live on the token and are addressed by `CKA_LABEL` (the API's
//! `key_id`); `CKA_ID` carries the same bytes for tools that search by id.
//! Private and secret keys are generated with `CKA_SENSITIVE = true` and
//! `CKA_EXTRACTABLE = false`, so the token itself refuses both
//! `C_GetAttributeValue(CKA_VALUE)` and `C_WrapKey` on them.
//! [`Pkcs11Backend::wrap_roundtrip`] records exactly those refusals.
//!
//! Hashing policy: for ECDSA and RSA-PSS the service hashes the payload with
//! SHA-256 and sends only the 32-byte digest to the token (`CKM_ECDSA`,
//! `CKM_RSA_PKCS_PSS`). The digest is not secret, the private key never leaves
//! the token either way, and it keeps the token round trip independent of
//! payload size. Ed25519 is a pure scheme (RFC 8032), so the whole message is
//! passed to `CKM_EDDSA`.

use std::collections::HashMap;
use std::os::raw::c_ulong;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass, ObjectHandle,
};
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use cryptoki::types::{AuthPin, Ulong};
use parking_lot::{Mutex, RwLock};

use crate::crypto::{
    self, sha256, ED25519_OID_DER, ED25519_POINT_LEN, P256_OID_DER, P256_POINT_LEN,
};
use crate::error::HsmError;
use crate::hsm::pool::{PoolOptions, PooledSession, SessionPool};
use crate::hsm::{
    Ciphertext, KeyBackend, KeyInfo, KeyKind, KeySpec, PoolStats, PublicKey, SigningAlgorithm,
    WrapRoundtrip,
};

const GCM_IV_LEN: usize = 12;
const GCM_TAG_BITS: c_ulong = 128;
const GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct Pkcs11Config {
    pub module: PathBuf,
    pub token_label: String,
    pub pool: PoolOptions,
}

pub struct Pkcs11Backend {
    pool: Arc<SessionPool>,
    /// `key_id -> kind`, populated by `provision`. Only provisioned keys are
    /// reachable through the API even if the token holds other objects.
    keys: RwLock<HashMap<String, KeyKind>>,
}

impl Pkcs11Backend {
    /// Loads the module, initializes the library, finds the token by label and
    /// opens the session pool. Blocking: call it from `spawn_blocking`.
    pub fn connect(cfg: &Pkcs11Config, pin: AuthPin) -> Result<Self, HsmError> {
        let ctx = load_module(&cfg.module)?;
        let slot = find_slot(&ctx, &cfg.token_label)?;
        let pool = SessionPool::new(ctx, slot, pin, cfg.pool.clone())?;
        Ok(Self {
            pool,
            keys: RwLock::new(HashMap::new()),
        })
    }

    pub fn pool(&self) -> &Arc<SessionPool> {
        &self.pool
    }

    fn kind_of(&self, key_id: &str) -> Result<KeyKind, HsmError> {
        self.keys
            .read()
            .get(key_id)
            .copied()
            .ok_or_else(|| HsmError::KeyNotFound(key_id.to_string()))
    }

    fn check_signing(&self, key_id: &str, algorithm: SigningAlgorithm) -> Result<(), HsmError> {
        let kind = self.kind_of(key_id)?;
        if algorithm.key_kind() != kind {
            return Err(HsmError::AlgorithmMismatch {
                key_id: key_id.to_string(),
                algorithm: algorithm.to_string(),
                kind: kind.to_string(),
            });
        }
        Ok(())
    }

    fn check_symmetric(&self, key_id: &str) -> Result<(), HsmError> {
        let kind = self.kind_of(key_id)?;
        if !kind.is_symmetric() {
            return Err(HsmError::AlgorithmMismatch {
                key_id: key_id.to_string(),
                algorithm: "AES_256_GCM".into(),
                kind: kind.to_string(),
            });
        }
        Ok(())
    }

    /// Verifies a signature *inside the token* with `C_Verify`, as an
    /// independent cross-check of the software verifier. Used by tests.
    pub async fn verify_in_token(
        &self,
        key_id: &str,
        algorithm: SigningAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<bool, HsmError> {
        self.check_signing(key_id, algorithm)?;
        let key_id = key_id.to_string();
        let input = signing_input(algorithm, payload);
        let signature = signature.to_vec();
        self.pool
            .with_session("verify", move |s| {
                let handle = find_object(s, ObjectClass::PUBLIC_KEY, &key_id)?;
                let result = with_mechanism(algorithm, |mech| {
                    s.session.verify(mech, handle, &input, &signature)
                });
                match result {
                    Ok(()) => Ok(true),
                    Err(Pkcs11Error::Pkcs11(
                        RvError::SignatureInvalid | RvError::SignatureLenRange,
                        _,
                    )) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }
}

#[async_trait]
impl KeyBackend for Pkcs11Backend {
    fn name(&self) -> &'static str {
        "pkcs11"
    }

    async fn provision(&self, specs: &[KeySpec]) -> Result<Vec<KeyInfo>, HsmError> {
        let mut out = Vec::with_capacity(specs.len());
        for spec in specs {
            let spec_c = spec.clone();
            let result = self
                .pool
                .with_session("provision", move |s| {
                    let class = if spec_c.kind.is_symmetric() {
                        ObjectClass::SECRET_KEY
                    } else {
                        ObjectClass::PRIVATE_KEY
                    };
                    let existing = s.session.find_objects(&[
                        Attribute::Class(class),
                        Attribute::Label(spec_c.id.as_bytes().to_vec()),
                    ])?;
                    let handle = match existing.as_slice() {
                        [] => {
                            generate_key(&s.session, &spec_c)?;
                            tracing::info!(key_id = %spec_c.id, kind = %spec_c.kind, "generated key inside the token");
                            find_object(s, class, &spec_c.id)?
                        }
                        [h] => {
                            tracing::debug!(key_id = %spec_c.id, kind = %spec_c.kind, "key already present on token");
                            *h
                        }
                        many => {
                            return Err(HsmError::Internal(format!(
                                "{} objects on the token share label {:?}",
                                many.len(),
                                spec_c.id
                            )))
                        }
                    };
                    read_key_info(&s.session, handle, &spec_c.id, spec_c.kind)
                })
                .await;
            match result {
                Ok(info) => {
                    if info.extractable || !info.sensitive {
                        // Refuse to serve a key whose protection is weaker than
                        // our policy, even if it carries the right label.
                        return Err(HsmError::Internal(format!(
                            "key {:?} on the token is extractable or not sensitive; refusing to use it",
                            spec.id
                        )));
                    }
                    self.keys.write().insert(spec.id.clone(), spec.kind);
                    out.push(info);
                }
                Err(e) if spec.optional => {
                    tracing::warn!(key_id = %spec.id, kind = %spec.kind, error = %e, "optional key skipped");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    async fn sign(
        &self,
        key_id: &str,
        algorithm: SigningAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        self.check_signing(key_id, algorithm)?;
        let key_id = key_id.to_string();
        let input = signing_input(algorithm, payload);
        self.pool
            .with_session("sign", move |s| {
                let handle = find_object(s, ObjectClass::PRIVATE_KEY, &key_id)?;
                let sig = with_mechanism(algorithm, |mech| s.session.sign(mech, handle, &input))?;
                Ok(sig)
            })
            .await
    }

    async fn public_key(&self, key_id: &str) -> Result<PublicKey, HsmError> {
        let kind = self.kind_of(key_id)?;
        if kind.is_symmetric() {
            return Err(HsmError::InvalidInput(format!(
                "key {key_id} is symmetric and has no public key"
            )));
        }
        let key_id = key_id.to_string();
        self.pool
            .with_session("public_key", move |s| {
                let handle = find_object(s, ObjectClass::PUBLIC_KEY, &key_id)?;
                read_public_key(&s.session, handle, kind)
            })
            .await
    }

    async fn encrypt(
        &self,
        key_id: &str,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Ciphertext, HsmError> {
        self.check_symmetric(key_id)?;
        let key_id = key_id.to_string();
        let plaintext = plaintext.to_vec();
        let aad = aad.to_vec();
        self.pool
            .with_session("encrypt", move |s| {
                let handle = find_object(s, ObjectClass::SECRET_KEY, &key_id)?;
                // The IV comes from the token's RNG, never from application state.
                let mut iv = [0u8; GCM_IV_LEN];
                s.session.generate_random_slice(&mut iv)?;
                let data = {
                    let params = GcmParams::new(&mut iv, &aad, Ulong::from(GCM_TAG_BITS))?;
                    s.session
                        .encrypt(&Mechanism::AesGcm(params), handle, &plaintext)?
                };
                Ok(Ciphertext {
                    iv: iv.to_vec(),
                    data,
                })
            })
            .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, HsmError> {
        self.check_symmetric(key_id)?;
        let mut iv: [u8; GCM_IV_LEN] = iv
            .try_into()
            .map_err(|_| HsmError::InvalidInput(format!("iv must be {GCM_IV_LEN} bytes")))?;
        if ciphertext.len() < GCM_TAG_LEN {
            return Err(HsmError::InvalidInput(
                "ciphertext is shorter than the GCM tag".into(),
            ));
        }
        let key_id = key_id.to_string();
        let ciphertext = ciphertext.to_vec();
        let aad = aad.to_vec();
        self.pool
            .with_session("decrypt", move |s| {
                let handle = find_object(s, ObjectClass::SECRET_KEY, &key_id)?;
                let params = GcmParams::new(&mut iv, &aad, Ulong::from(GCM_TAG_BITS))?;
                match s
                    .session
                    .decrypt(&Mechanism::AesGcm(params), handle, &ciphertext)
                {
                    Ok(pt) => Ok(pt),
                    // Tag mismatch is a client-side error, not a token fault, so
                    // it must not look like a session failure to the pool.
                    Err(Pkcs11Error::Pkcs11(
                        rv @ (RvError::EncryptedDataInvalid
                        | RvError::EncryptedDataLenRange
                        | RvError::GeneralError
                        | RvError::FunctionFailed),
                        _,
                    )) => {
                        tracing::debug!(rv = ?rv, "AES-GCM decrypt rejected by token");
                        Err(HsmError::DecryptFailed)
                    }
                    Err(e) => Err(e.into()),
                }
            })
            .await
    }

    async fn list_keys(&self) -> Result<Vec<KeyInfo>, HsmError> {
        let mut registered: Vec<(String, KeyKind)> = self
            .keys
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        registered.sort_by(|a, b| a.0.cmp(&b.0));
        self.pool
            .with_session("list_keys", move |s| {
                let mut out = Vec::with_capacity(registered.len());
                for (key_id, kind) in registered {
                    let class = if kind.is_symmetric() {
                        ObjectClass::SECRET_KEY
                    } else {
                        ObjectClass::PRIVATE_KEY
                    };
                    let handle = find_object(s, class, &key_id)?;
                    out.push(read_key_info(&s.session, handle, &key_id, kind)?);
                }
                Ok(out)
            })
            .await
    }

    async fn wrap_roundtrip(&self, kek_id: &str) -> Result<WrapRoundtrip, HsmError> {
        self.check_symmetric(kek_id)?;
        let kek_id = kek_id.to_string();
        self.pool
            .with_session("wrap_roundtrip", move |s| {
                let kek = find_object(s, ObjectClass::SECRET_KEY, &kek_id)?;
                wrap_roundtrip_sync(&s.session, kek, &kek_id)
            })
            .await
    }

    async fn health(&self) -> Result<(), HsmError> {
        self.pool
            .with_session("health", |s| {
                s.session.get_session_info()?;
                Ok(())
            })
            .await
    }

    fn pool_stats(&self) -> PoolStats {
        self.pool.stats()
    }
}

/// Loads a PKCS#11 module once per process and keeps it loaded for the
/// lifetime of the process.
///
/// Two PKCS#11 facts drive this:
///
/// * `C_Initialize`/`C_Finalize` are per *process*, not per handle. Every
///   backend instance in a process (there is normally one; tests create more)
///   must share the same initialized context.
/// * PKCS#11 modules are not safe to unload. SoftHSM2 (via OpenSSL) and most
///   vendor libraries register thread-local destructors and `atexit` handlers
///   that point into the module; `dlclose` followed by a thread or process
///   exit then crashes in `pthread` cleanup. Keeping a clone in a static means
///   the context is never dropped, so the module is never finalized or
///   unloaded -- the operating system reclaims it at process exit.
fn load_module(path: &Path) -> Result<Pkcs11, HsmError> {
    static MODULES: Mutex<Vec<(PathBuf, Pkcs11)>> = Mutex::new(Vec::new());
    let mut modules = MODULES.lock();
    if let Some((_, ctx)) = modules.iter().find(|(p, _)| p == path) {
        return Ok(ctx.clone());
    }
    let ctx = Pkcs11::new(path).map_err(|e| {
        HsmError::Unavailable(format!(
            "cannot load PKCS#11 module {}: {e}",
            path.display()
        ))
    })?;
    // OS_LOCKING_OK lets the library use native mutexes so that different
    // sessions may be driven from different threads concurrently.
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(HsmError::Unavailable(format!("C_Initialize failed: {e}"))),
    }
    if let Ok(info) = ctx.get_library_info() {
        tracing::info!(
            module = %path.display(),
            manufacturer = info.manufacturer_id().trim(),
            library = info.library_description().trim(),
            version = ?info.library_version(),
            "PKCS#11 module loaded"
        );
    }
    modules.push((path.to_path_buf(), ctx.clone()));
    Ok(ctx)
}

fn find_slot(ctx: &Pkcs11, label: &str) -> Result<Slot, HsmError> {
    let mut seen = Vec::new();
    for slot in ctx.get_slots_with_initialized_token()? {
        let info = ctx.get_token_info(slot)?;
        let token_label = info.label().trim().to_string();
        if token_label == label {
            tracing::info!(
                slot = slot.id(),
                token = %token_label,
                model = info.model().trim(),
                serial = info.serial_number().trim(),
                "token found"
            );
            return Ok(slot);
        }
        seen.push(token_label);
    }
    Err(HsmError::Unavailable(format!(
        "no initialized token labelled {label:?} (tokens present: {seen:?})"
    )))
}

/// What is actually handed to the token for a given algorithm.
fn signing_input(algorithm: SigningAlgorithm, payload: &[u8]) -> Vec<u8> {
    if algorithm.prehash() {
        sha256(payload).to_vec()
    } else {
        payload.to_vec()
    }
}

/// Builds the PKCS#11 mechanism for `algorithm` and runs `f` with it. The
/// mechanism borrows its parameters, hence the callback shape.
fn with_mechanism<T>(
    algorithm: SigningAlgorithm,
    f: impl FnOnce(&Mechanism<'_>) -> Result<T, Pkcs11Error>,
) -> Result<T, Pkcs11Error> {
    match algorithm {
        SigningAlgorithm::EcdsaP256Sha256 => f(&Mechanism::Ecdsa),
        SigningAlgorithm::RsaPssSha256 => f(&Mechanism::RsaPkcsPss(PkcsPssParams {
            hash_alg: MechanismType::SHA256,
            mgf: PkcsMgfType::MGF1_SHA256,
            s_len: Ulong::from(32 as c_ulong),
        })),
        SigningAlgorithm::Ed25519 => f(&Mechanism::Eddsa(EddsaParams::new(
            EddsaSignatureScheme::Pure,
        ))),
    }
}

/// Finds the single object of `class` labelled `key_id`, caching the handle in
/// the session. Ambiguity (duplicate labels) is treated as an error rather than
/// silently picking one.
fn find_object(
    s: &mut PooledSession,
    class: ObjectClass,
    key_id: &str,
) -> Result<ObjectHandle, HsmError> {
    let cache_key = format!("{class}:{key_id}");
    if let Some(h) = s.cached_handle(&cache_key) {
        return Ok(h);
    }
    let found = s.session.find_objects(&[
        Attribute::Class(class),
        Attribute::Label(key_id.as_bytes().to_vec()),
    ])?;
    match found.as_slice() {
        [] => Err(HsmError::KeyNotFound(key_id.to_string())),
        [h] => {
            s.cache_handle(cache_key, *h);
            Ok(*h)
        }
        many => Err(HsmError::Internal(format!(
            "{} objects on the token share label {key_id:?}; refusing to pick one",
            many.len()
        ))),
    }
}

/// Generates a key (pair) for `spec` inside the token.
fn generate_key(session: &Session, spec: &KeySpec) -> Result<(), HsmError> {
    let label = Attribute::Label(spec.id.as_bytes().to_vec());
    let id = Attribute::Id(spec.id.as_bytes().to_vec());

    // Policy shared by every private/secret key: persistent token object,
    // login-protected, value never readable, never wrappable out.
    let protected = |extra: &[Attribute]| -> Vec<Attribute> {
        let mut t = vec![
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            label.clone(),
            id.clone(),
        ];
        t.extend_from_slice(extra);
        t
    };
    let public = |extra: &[Attribute]| -> Vec<Attribute> {
        let mut t = vec![
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            label.clone(),
            id.clone(),
        ];
        t.extend_from_slice(extra);
        t
    };

    match spec.kind {
        KeyKind::EcdsaP256 => {
            session.generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public(&[Attribute::EcParams(P256_OID_DER.to_vec())]),
                &protected(&[Attribute::Sign(true)]),
            )?;
        }
        KeyKind::Ed25519 => {
            session.generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &public(&[
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::EcParams(ED25519_OID_DER.to_vec()),
                ]),
                &protected(&[
                    Attribute::KeyType(KeyType::EC_EDWARDS),
                    Attribute::Sign(true),
                ]),
            )?;
        }
        KeyKind::Rsa3072 => {
            session.generate_key_pair(
                &Mechanism::RsaPkcsKeyPairGen,
                &public(&[
                    Attribute::ModulusBits(Ulong::from(3072 as c_ulong)),
                    Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                ]),
                &protected(&[Attribute::Sign(true)]),
            )?;
        }
        KeyKind::Aes256 => {
            session.generate_key(
                &Mechanism::AesKeyGen,
                &protected(&[
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::Wrap(true),
                    Attribute::Unwrap(true),
                    Attribute::ValueLen(Ulong::from(32 as c_ulong)),
                ]),
            )?;
        }
    }
    Ok(())
}

/// Reads the protection attributes of a private/secret key. Defaults are
/// pessimistic so a token that omits an attribute never looks safer than it is.
fn read_key_info(
    session: &Session,
    handle: ObjectHandle,
    key_id: &str,
    kind: KeyKind,
) -> Result<KeyInfo, HsmError> {
    let attrs = session.get_attributes(
        handle,
        &[
            AttributeType::Sensitive,
            AttributeType::Extractable,
            AttributeType::NeverExtractable,
            AttributeType::Local,
            AttributeType::Token,
        ],
    )?;
    let mut info = KeyInfo {
        key_id: key_id.to_string(),
        kind,
        algorithms: kind.algorithms().to_vec(),
        sensitive: false,
        extractable: true,
        never_extractable: false,
        local: false,
        token_object: false,
    };
    for a in attrs {
        match a {
            Attribute::Sensitive(v) => info.sensitive = v,
            Attribute::Extractable(v) => info.extractable = v,
            Attribute::NeverExtractable(v) => info.never_extractable = v,
            Attribute::Local(v) => info.local = v,
            Attribute::Token(v) => info.token_object = v,
            _ => {}
        }
    }
    Ok(info)
}

fn read_public_key(
    session: &Session,
    handle: ObjectHandle,
    kind: KeyKind,
) -> Result<PublicKey, HsmError> {
    let missing =
        |what: &str| HsmError::Internal(format!("token did not return {what} for the public key"));
    match kind {
        KeyKind::EcdsaP256 | KeyKind::Ed25519 => {
            let attrs = session.get_attributes(handle, &[AttributeType::EcPoint])?;
            let point = attrs
                .iter()
                .find_map(|a| match a {
                    Attribute::EcPoint(p) => Some(p.as_slice()),
                    _ => None,
                })
                .ok_or_else(|| missing("CKA_EC_POINT"))?;
            if kind == KeyKind::EcdsaP256 {
                Ok(PublicKey::EcdsaP256 {
                    sec1: crypto::ec_point_contents(point, P256_POINT_LEN)?.to_vec(),
                })
            } else {
                let bytes: [u8; 32] = crypto::ec_point_contents(point, ED25519_POINT_LEN)?
                    .try_into()
                    .map_err(|_| missing("a 32-byte Ed25519 point"))?;
                Ok(PublicKey::Ed25519 { bytes })
            }
        }
        KeyKind::Rsa3072 => {
            let attrs = session.get_attributes(
                handle,
                &[AttributeType::Modulus, AttributeType::PublicExponent],
            )?;
            let mut modulus = None;
            let mut exponent = None;
            for a in attrs {
                match a {
                    Attribute::Modulus(n) => modulus = Some(n),
                    Attribute::PublicExponent(e) => exponent = Some(e),
                    _ => {}
                }
            }
            Ok(PublicKey::Rsa {
                modulus: modulus.ok_or_else(|| missing("CKA_MODULUS"))?,
                exponent: exponent.ok_or_else(|| missing("CKA_PUBLIC_EXPONENT"))?,
            })
        }
        KeyKind::Aes256 => Err(HsmError::InvalidInput(
            "symmetric keys have no public key".into(),
        )),
    }
}

/// The wrap/unwrap workflow, entirely inside one session:
///
/// 1. generate an ephemeral, extractable data-encryption key (DEK) as a
///    session object and encrypt a sample under it;
/// 2. wrap the DEK under the non-extractable KEK with `CKM_AES_KEY_WRAP_PAD`
///    (RFC 5649) -- the only form in which the DEK ever leaves the token;
/// 3. destroy the original DEK;
/// 4. unwrap the blob into a new, *non-extractable* session key;
/// 5. decrypt the sample under the unwrapped copy;
/// 6. ask the token to wrap the KEK and to reveal its `CKA_VALUE`, recording
///    the refusals.
fn wrap_roundtrip_sync(
    session: &Session,
    kek: ObjectHandle,
    kek_id: &str,
) -> Result<WrapRoundtrip, HsmError> {
    let dek = session.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
            Attribute::Encrypt(true),
            Attribute::ValueLen(Ulong::from(32 as c_ulong)),
            Attribute::Label(b"wrap-roundtrip-dek".to_vec()),
        ],
    )?;
    let result = wrap_roundtrip_inner(session, kek, kek_id, dek);
    if result.is_err() {
        // Best effort: session objects die with the session anyway.
        let _ = session.destroy_object(dek);
    }
    result
}

fn wrap_roundtrip_inner(
    session: &Session,
    kek: ObjectHandle,
    kek_id: &str,
    dek: ObjectHandle,
) -> Result<WrapRoundtrip, HsmError> {
    let sample = b"wrap-roundtrip sample data";
    let mut iv = [0u8; GCM_IV_LEN];
    session.generate_random_slice(&mut iv)?;
    let ciphertext = {
        let params = GcmParams::new(&mut iv, &[], Ulong::from(GCM_TAG_BITS))?;
        session.encrypt(&Mechanism::AesGcm(params), dek, sample)?
    };

    let wrapped = session.wrap_key(&Mechanism::AesKeyWrapPad, kek, dek)?;
    session.destroy_object(dek)?;

    let unwrapped = session.unwrap_key(
        &Mechanism::AesKeyWrapPad,
        kek,
        &wrapped,
        &[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Decrypt(true),
            Attribute::Wrap(true),
            Attribute::Label(b"wrap-roundtrip-dek-unwrapped".to_vec()),
        ],
    )?;

    let roundtrip_ok = {
        let params = GcmParams::new(&mut iv, &[], Ulong::from(GCM_TAG_BITS))?;
        matches!(
            session.decrypt(&Mechanism::AesGcm(params), unwrapped, &ciphertext),
            Ok(pt) if pt == sample
        )
    };

    // Negative proofs: the KEK must refuse to be wrapped (even by a key that is
    // allowed to wrap) and must refuse to reveal its value.
    let kek_wrap_attempt = match session.wrap_key(&Mechanism::AesKeyWrapPad, unwrapped, kek) {
        Ok(bytes) => format!("UNEXPECTED: token wrapped the KEK ({} bytes)", bytes.len()),
        Err(Pkcs11Error::Pkcs11(rv, _)) => format!("rejected: {rv:?}"),
        Err(e) => format!("rejected: {e}"),
    };
    let kek_value_read_attempt = match session.get_attribute_info(kek, &[AttributeType::Value]) {
        Ok(infos) => match infos.first() {
            Some(AttributeInfo::Sensitive) => "rejected: CKR_ATTRIBUTE_SENSITIVE".to_string(),
            Some(AttributeInfo::Available(n)) => {
                format!("UNEXPECTED: token reports CKA_VALUE readable ({n} bytes)")
            }
            other => format!("rejected: {other:?}"),
        },
        Err(e) => format!("rejected: {e}"),
    };

    let _ = session.destroy_object(unwrapped);

    Ok(WrapRoundtrip {
        kek_id: kek_id.to_string(),
        wrap_mechanism: "CKM_AES_KEY_WRAP_PAD",
        wrapped_key_len: wrapped.len(),
        roundtrip_ok,
        kek_wrap_attempt,
        kek_value_read_attempt,
    })
}
