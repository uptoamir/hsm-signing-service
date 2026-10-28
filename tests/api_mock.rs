//! HTTP API tests against the in-memory mock backend. No token required.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hsm_signer::api::{router, ApiOptions, AppState};
use hsm_signer::hsm::mock::MockBackend;
use hsm_signer::hsm::{KeyBackend, KeyKind, KeySpec};
use hsm_signer::telemetry;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const MAX_BODY: usize = 64 * 1024;

fn spec(id: &str, kind: KeyKind) -> KeySpec {
    KeySpec {
        id: id.into(),
        kind,
        optional: false,
    }
}

async fn app_with(backend: MockBackend) -> axum::Router {
    backend
        .provision(&[
            spec("ec", KeyKind::EcdsaP256),
            spec("kek", KeyKind::Aes256),
            spec("ed", KeyKind::Ed25519),
        ])
        .await
        .unwrap();
    let state = AppState {
        backend: Arc::new(backend),
        metrics: telemetry::metrics_handle(),
        started: Instant::now(),
    };
    router(
        state,
        &ApiOptions {
            max_body_bytes: MAX_BODY,
            request_timeout: Duration::from_secs(5),
        },
    )
}

async fn app() -> axum::Router {
    app_with(MockBackend::new(
        Duration::ZERO,
        4,
        Duration::from_millis(200),
    ))
    .await
}

async fn call(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, json, headers)
}

fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

#[tokio::test]
async fn sign_then_verify_der_and_raw() {
    let app = app().await;
    let payload = b64(b"hello arkion");

    let (status, body, headers) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.contains_key("x-request-id"));
    assert_eq!(body["key_id"], "ec");
    assert_eq!(body["algorithm"], "ECDSA_P256_SHA256");
    assert_eq!(body["signature_format"], "der");
    assert!(body["duration_ms"].is_number());
    let der = B64.decode(body["signature"].as_str().unwrap()).unwrap();
    assert_eq!(der[0], 0x30, "DER SEQUENCE expected");

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/verify",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": payload, "signature": b64(&der)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);

    let (_, body, _) = call(
        &app,
        "POST",
        "/v1/verify",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": b64(b"other"), "signature": b64(&der)})),
    )
    .await;
    assert_eq!(body["valid"], false);

    // Garbage that is not DER must be reported as invalid, not as an error.
    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/verify",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": payload, "signature": b64(&[1, 2, 3])})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], false);

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": payload, "signature_format": "raw"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["signature_format"], "raw");
    let raw = B64.decode(body["signature"].as_str().unwrap()).unwrap();
    assert_eq!(raw.len(), 64);
    let (_, body, _) = call(
        &app,
        "POST",
        "/v1/verify",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": payload, "signature": b64(&raw), "signature_format": "raw"})),
    )
    .await;
    assert_eq!(body["valid"], true);
}

#[tokio::test]
async fn ed25519_sign_verify() {
    let app = app().await;
    let payload = b64(b"pure eddsa");
    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ed", "algorithm": "ED25519", "payload": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["signature_format"], "raw");
    let sig = body["signature"].as_str().unwrap().to_string();
    assert_eq!(B64.decode(&sig).unwrap().len(), 64);
    let (_, body, _) = call(
        &app,
        "POST",
        "/v1/verify",
        Some(json!({"key_id": "ed", "algorithm": "ED25519", "payload": payload, "signature": sig})),
    )
    .await;
    assert_eq!(body["valid"], true);
}

#[tokio::test]
async fn input_validation_errors() {
    let app = app().await;
    let payload = b64(b"x");

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "nope", "algorithm": "ECDSA_P256_SHA256", "payload": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "KEY_NOT_FOUND");

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": "not base64!!"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "INVALID_INPUT");

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ed", "algorithm": "ECDSA_P256_SHA256", "payload": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "ALGORITHM_MISMATCH");

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "MD5_RSA", "payload": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, _, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": payload, "pin": "1234"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "unknown fields are rejected"
    );

    let (status, _, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "../etc", "algorithm": "ECDSA_P256_SHA256", "payload": payload})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "key ids are validated");

    let (status, _, _) = call(&app, "GET", "/v1/keys/kek/public", None).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "symmetric keys have no public key"
    );
}

#[tokio::test]
async fn body_limit_is_enforced() {
    let app = app().await;
    let huge = b64(&vec![0u8; MAX_BODY]);
    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": huge})),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"]["code"], "PAYLOAD_TOO_LARGE");
}

#[tokio::test]
async fn aes_gcm_encrypt_decrypt() {
    let app = app().await;
    let plaintext = b64(b"top secret");
    let aad = b64(b"context");
    let (status, enc, _) = call(
        &app,
        "POST",
        "/v1/encrypt",
        Some(json!({"key_id": "kek", "plaintext": plaintext, "aad": aad})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enc}");
    assert_eq!(enc["algorithm"], "AES_256_GCM");
    assert_eq!(B64.decode(enc["iv"].as_str().unwrap()).unwrap().len(), 12);

    let (status, dec, _) = call(
        &app,
        "POST",
        "/v1/decrypt",
        Some(
            json!({"key_id": "kek", "iv": enc["iv"], "ciphertext": enc["ciphertext"], "aad": aad}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{dec}");
    assert_eq!(dec["plaintext"], plaintext);

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/decrypt",
        Some(json!({"key_id": "kek", "iv": enc["iv"], "ciphertext": enc["ciphertext"], "aad": b64(b"wrong")})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "DECRYPT_FAILED");

    let mut ct = B64.decode(enc["ciphertext"].as_str().unwrap()).unwrap();
    ct[0] ^= 0x01;
    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/decrypt",
        Some(json!({"key_id": "kek", "iv": enc["iv"], "ciphertext": b64(&ct), "aad": aad})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "DECRYPT_FAILED");

    let (status, body, _) = call(
        &app,
        "POST",
        "/v1/encrypt",
        Some(json!({"key_id": "ec", "plaintext": plaintext})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[tokio::test]
async fn keys_public_and_wrap_roundtrip() {
    let app = app().await;
    let (status, body, _) = call(&app, "GET", "/v1/keys", None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    for k in keys {
        assert_eq!(k["extractable"], false);
        assert_eq!(k["sensitive"], true);
    }

    let (status, body, _) = call(&app, "GET", "/v1/keys/ec/public", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["public_key_pem"]
        .as_str()
        .unwrap()
        .starts_with("-----BEGIN PUBLIC KEY-----"));
    assert_eq!(body["kind"], "ecdsa-p256");

    let (status, body, _) = call(&app, "POST", "/v1/keys/kek/wrap-roundtrip", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["roundtrip_ok"], true);
    assert!(body["kek_wrap_attempt"]
        .as_str()
        .unwrap()
        .starts_with("rejected"));
}

#[tokio::test]
async fn health_ready_metrics() {
    let app = app().await;
    let (status, body, _) = call(&app, "GET", "/healthz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    let (status, body, _) = call(&app, "GET", "/readyz", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["pool"]["capacity"], 4);

    let _ = call(
        &app,
        "POST",
        "/v1/sign",
        Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": b64(b"m")})),
    )
    .await;
    let (status, body, _) = call(&app, "GET", "/metrics", None).await;
    assert_eq!(status, StatusCode::OK);
    let text = body.as_str().unwrap();
    assert!(text.contains("http_requests_total"), "{text}");
    assert!(text.contains("hsm_pool_capacity"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saturated_pool_returns_503_with_retry_after() {
    // One "session", 300 ms per operation, callers give up after 50 ms.
    let app = app_with(MockBackend::new(
        Duration::from_millis(300),
        1,
        Duration::from_millis(50),
    ))
    .await;
    let req = || {
        call(
            &app,
            "POST",
            "/v1/sign",
            Some(json!({"key_id": "ec", "algorithm": "ECDSA_P256_SHA256", "payload": b64(b"m")})),
        )
    };
    let (a, b, c) = tokio::join!(req(), req(), req());
    let results = [a, b, c];
    let ok = results
        .iter()
        .filter(|(s, _, _)| *s == StatusCode::OK)
        .count();
    let busy: Vec<_> = results
        .iter()
        .filter(|(s, _, _)| *s == StatusCode::SERVICE_UNAVAILABLE)
        .collect();
    assert_eq!(ok, 1, "exactly one request gets the single session");
    assert_eq!(busy.len(), 2, "the others are shed");
    for (_, body, headers) in &busy {
        assert_eq!(body["error"]["code"], "HSM_BUSY");
        assert_eq!(headers.get("retry-after").unwrap(), "1");
    }
}
