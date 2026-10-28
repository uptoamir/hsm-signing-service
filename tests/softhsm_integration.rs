//! End-to-end test against SoftHSM2 through PKCS#11.
//!
//! Requirements: `softhsm2-util` on `PATH` and the SoftHSM2 module at
//! `PKCS11_MODULE` (or a well-known location). A throw-away token is created
//! in a temporary directory, so the test never touches an existing token.
//! When SoftHSM2 is unavailable the test is skipped with a message, unless
//! `HSM_TEST_REQUIRE=1` is set, in which case it fails.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cryptoki::types::AuthPin;
use hsm_signer::api::{router, ApiOptions, AppState};
use hsm_signer::crypto;
use hsm_signer::error::HsmError;
use hsm_signer::hsm::pkcs11::{Pkcs11Backend, Pkcs11Config};
use hsm_signer::hsm::pool::PoolOptions;
use hsm_signer::hsm::{KeyBackend, KeyKind, KeySpec, SigningAlgorithm};
use hsm_signer::telemetry;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

const USER_PIN: &str = "1234";
const LABEL: &str = "arkion-test";

fn module_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PKCS11_MODULE") {
        return Some(PathBuf::from(p));
    }
    [
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

struct TestToken {
    _dir: tempfile::TempDir,
    module: PathBuf,
}

fn setup_token() -> Option<TestToken> {
    let module = module_path()?;
    Command::new("softhsm2-util")
        .arg("--version")
        .output()
        .ok()?;
    let dir = tempfile::tempdir().expect("tempdir");
    let tokens = dir.path().join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let conf = dir.path().join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();
    // The library reads this at C_Initialize; set it before loading the module.
    std::env::set_var("SOFTHSM2_CONF", &conf);
    let status = Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            LABEL,
            "--so-pin",
            "0102030405",
            "--pin",
            USER_PIN,
        ])
        .env("SOFTHSM2_CONF", &conf)
        .status()
        .expect("run softhsm2-util");
    assert!(status.success(), "softhsm2-util --init-token failed");
    Some(TestToken { _dir: dir, module })
}

fn connect(token: &TestToken, capacity: usize, acquire: Duration, op: Duration) -> Pkcs11Backend {
    Pkcs11Backend::connect(
        &Pkcs11Config {
            module: token.module.clone(),
            token_label: LABEL.into(),
            pool: PoolOptions {
                capacity,
                acquire_timeout: acquire,
                op_timeout: op,
            },
        },
        AuthPin::from(USER_PIN.to_string()),
    )
    .expect("connect to SoftHSM2")
}

fn specs() -> Vec<KeySpec> {
    let s = |id: &str, kind, optional| KeySpec {
        id: id.into(),
        kind,
        optional,
    };
    vec![
        s("it-ec", KeyKind::EcdsaP256, false),
        s("it-kek", KeyKind::Aes256, false),
        s("it-rsa", KeyKind::Rsa3072, true),
        s("it-ed", KeyKind::Ed25519, true),
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn softhsm_end_to_end() {
    let Some(token) = setup_token() else {
        if std::env::var("HSM_TEST_REQUIRE").as_deref() == Ok("1") {
            panic!("SoftHSM2 is required (HSM_TEST_REQUIRE=1) but not available");
        }
        eprintln!("SKIPPED: SoftHSM2 (softhsm2-util + module) not available");
        return;
    };

    // --- provisioning -----------------------------------------------------
    let backend = Arc::new(connect(
        &token,
        4,
        Duration::from_secs(2),
        Duration::from_secs(10),
    ));
    let infos = backend.provision(&specs()).await.expect("provision");
    assert!(infos.iter().any(|k| k.key_id == "it-ec"));
    assert!(infos.iter().any(|k| k.key_id == "it-kek"));
    for k in &infos {
        eprintln!("provisioned {} ({}): {k:?}", k.key_id, k.kind);
        assert!(k.sensitive, "{} must be CKA_SENSITIVE", k.key_id);
        assert!(!k.extractable, "{} must not be CKA_EXTRACTABLE", k.key_id);
        assert!(
            k.never_extractable,
            "{} must be CKA_NEVER_EXTRACTABLE",
            k.key_id
        );
        assert!(k.local, "{} must be generated on the token", k.key_id);
        assert!(
            k.token_object,
            "{} must be a persistent token object",
            k.key_id
        );
    }

    // --- signing: software verify + in-token C_Verify cross-check ----------
    let payload = b"integration payload";
    for k in infos.iter().filter(|k| !k.kind.is_symmetric()) {
        let public = backend.public_key(&k.key_id).await.expect("public key");
        let pem = crypto::public_key_pem(&public).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        for alg in &k.algorithms {
            let sig = backend.sign(&k.key_id, *alg, payload).await.expect("sign");
            match alg {
                SigningAlgorithm::EcdsaP256Sha256 => {
                    assert_eq!(sig.len(), 64);
                    let der = crypto::ecdsa_raw_to_der(&sig).unwrap();
                    assert_eq!(crypto::ecdsa_der_to_raw(&der).unwrap(), sig);
                }
                SigningAlgorithm::Ed25519 => assert_eq!(sig.len(), 64),
                SigningAlgorithm::RsaPssSha256 => assert_eq!(sig.len(), 384),
            }
            assert!(
                crypto::verify(&public, *alg, payload, &sig).unwrap(),
                "{alg} software verify"
            );
            assert!(
                !crypto::verify(&public, *alg, b"forged", &sig).unwrap(),
                "{alg} forged payload"
            );
            assert!(
                backend
                    .verify_in_token(&k.key_id, *alg, payload, &sig)
                    .await
                    .unwrap(),
                "{alg} C_Verify"
            );
            let mut bad = sig.clone();
            bad[5] ^= 0x40;
            assert!(
                !backend
                    .verify_in_token(&k.key_id, *alg, payload, &bad)
                    .await
                    .unwrap(),
                "{alg} C_Verify tampered"
            );
        }
    }

    // Algorithm/key mismatch is caught before touching the token.
    assert!(matches!(
        backend
            .sign("it-kek", SigningAlgorithm::EcdsaP256Sha256, payload)
            .await,
        Err(HsmError::AlgorithmMismatch { .. })
    ));
    assert!(matches!(
        backend
            .sign("missing", SigningAlgorithm::EcdsaP256Sha256, payload)
            .await,
        Err(HsmError::KeyNotFound(_))
    ));

    // --- AES-256-GCM inside the token ----------------------------------------
    let ct1 = backend
        .encrypt("it-kek", b"plaintext", b"aad")
        .await
        .expect("encrypt");
    let ct2 = backend
        .encrypt("it-kek", b"plaintext", b"aad")
        .await
        .expect("encrypt");
    assert_eq!(ct1.iv.len(), 12);
    assert_ne!(ct1.iv, ct2.iv, "fresh IV per encryption");
    assert_eq!(ct1.data.len(), b"plaintext".len() + 16);
    assert_eq!(
        backend
            .decrypt("it-kek", &ct1.iv, &ct1.data, b"aad")
            .await
            .unwrap(),
        b"plaintext"
    );
    assert!(matches!(
        backend
            .decrypt("it-kek", &ct1.iv, &ct1.data, b"wrong")
            .await,
        Err(HsmError::DecryptFailed)
    ));
    let mut tampered = ct1.data.clone();
    tampered[0] ^= 1;
    assert!(matches!(
        backend.decrypt("it-kek", &ct1.iv, &tampered, b"aad").await,
        Err(HsmError::DecryptFailed)
    ));
    assert!(matches!(
        backend
            .decrypt("it-kek", &ct1.iv[..8], &ct1.data, b"aad")
            .await,
        Err(HsmError::InvalidInput(_))
    ));

    // --- key wrapping + non-exportability proofs -----------------------------
    let wrap = backend
        .wrap_roundtrip("it-kek")
        .await
        .expect("wrap roundtrip");
    eprintln!("wrap roundtrip: {wrap:?}");
    assert!(wrap.roundtrip_ok);
    assert_eq!(wrap.wrapped_key_len, 40, "RFC 5649 wrap of a 32-byte key");
    assert!(
        wrap.kek_wrap_attempt.starts_with("rejected"),
        "{}",
        wrap.kek_wrap_attempt
    );
    assert!(
        wrap.kek_wrap_attempt.contains("KeyUnextractable"),
        "{}",
        wrap.kek_wrap_attempt
    );
    assert_eq!(
        wrap.kek_value_read_attempt,
        "rejected: CKR_ATTRIBUTE_SENSITIVE"
    );

    // --- concurrency through the pool ----------------------------------------
    let mut tasks = Vec::new();
    for i in 0..64u32 {
        let b = Arc::clone(&backend);
        tasks.push(tokio::spawn(async move {
            let msg = i.to_be_bytes();
            let sig = b
                .sign("it-ec", SigningAlgorithm::EcdsaP256Sha256, &msg)
                .await?;
            let public = b.public_key("it-ec").await?;
            crypto::verify(&public, SigningAlgorithm::EcdsaP256Sha256, &msg, &sig)
        }));
    }
    for t in tasks {
        assert!(t.await.unwrap().expect("concurrent sign"));
    }
    let stats = backend.pool_stats();
    eprintln!("pool stats after burst: {stats:?}");
    assert_eq!(stats.capacity, 4);
    assert_eq!(stats.sessions_recycled, 0);
    assert_eq!(stats.acquire_timeouts, 0);
    assert_eq!(stats.in_use, 0);
    assert_eq!(stats.idle, 4);
    backend.health().await.expect("health");

    // --- backpressure and operation timeout (second, tiny pool) --------------
    let small = Arc::new(connect(
        &token,
        1,
        Duration::from_millis(50),
        Duration::from_millis(150),
    ));
    let same_specs = specs();
    small
        .provision(&same_specs)
        .await
        .expect("re-provision finds existing keys");
    assert_eq!(
        public_bytes(&backend.public_key("it-ec").await.unwrap()),
        public_bytes(&small.public_key("it-ec").await.unwrap()),
        "second connection sees the same persisted key"
    );
    let hog = Arc::clone(&small);
    let hog_task = tokio::spawn(async move {
        hog.pool()
            .with_session("test_hog", |_s| {
                std::thread::sleep(Duration::from_millis(400));
                Ok(())
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    let started = Instant::now();
    let shed = small
        .sign("it-ec", SigningAlgorithm::EcdsaP256Sha256, payload)
        .await;
    assert!(matches!(shed, Err(HsmError::Busy(_))), "{shed:?}");
    assert!(
        started.elapsed() < Duration::from_millis(300),
        "shed quickly, not after the hog finished"
    );
    // The hog itself exceeds op_timeout: the caller gets Timeout, the permit
    // is released only when the blocking call returns.
    assert!(matches!(hog_task.await.unwrap(), Err(HsmError::Timeout(_))));
    tokio::time::sleep(Duration::from_millis(450)).await;
    small
        .sign("it-ec", SigningAlgorithm::EcdsaP256Sha256, payload)
        .await
        .expect("pool usable again after timeout");
    let stats = small.pool_stats();
    assert_eq!(stats.acquire_timeouts, 1);
    assert_eq!(stats.in_use, 0);

    // --- the HTTP API in front of the real token -----------------------------
    let app = router(
        AppState {
            backend: backend.clone(),
            metrics: telemetry::metrics_handle(),
            started: Instant::now(),
        },
        &ApiOptions {
            max_body_bytes: 1 << 20,
            request_timeout: Duration::from_secs(10),
        },
    );
    let post = |path: &str, body: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let res = app
        .clone()
        .oneshot(post(
            "/v1/sign",
            json!({"key_id": "it-ec", "algorithm": "ECDSA_P256_SHA256", "payload": B64.encode(payload)}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let res = app
        .clone()
        .oneshot(post(
            "/v1/verify",
            json!({"key_id": "it-ec", "algorithm": "ECDSA_P256_SHA256", "payload": B64.encode(payload), "signature": body["signature"]}),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["valid"], true);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/keys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap();
    for k in body["keys"].as_array().unwrap() {
        assert_eq!(k["extractable"], false, "{k}");
        assert_eq!(k["sensitive"], true, "{k}");
    }
}

fn public_bytes(p: &hsm_signer::hsm::PublicKey) -> Vec<u8> {
    match p {
        hsm_signer::hsm::PublicKey::EcdsaP256 { sec1 } => sec1.clone(),
        hsm_signer::hsm::PublicKey::Rsa { modulus, .. } => modulus.clone(),
        hsm_signer::hsm::PublicKey::Ed25519 { bytes } => bytes.to_vec(),
    }
}
