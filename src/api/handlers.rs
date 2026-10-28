use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use super::dto::*;
use super::{ApiError, AppState};
use crate::crypto;
use crate::error::HsmError;
use crate::hsm::{validate_key_id, SigningAlgorithm};

const AES_GCM: &str = "AES_256_GCM";

fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0
}

fn b64_decode(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(value)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid base64")))
}

fn b64_decode_opt(field: &str, value: &Option<String>) -> Result<Vec<u8>, ApiError> {
    match value {
        Some(v) => b64_decode(field, v),
        None => Ok(Vec::new()),
    }
}

/// Applies the requested encoding to a raw signature.
fn encode_signature(
    algorithm: SigningAlgorithm,
    requested: SignatureFormat,
    raw: Vec<u8>,
) -> Result<(Vec<u8>, SignatureFormat), ApiError> {
    match (algorithm, requested) {
        (SigningAlgorithm::EcdsaP256Sha256, SignatureFormat::Der) => {
            Ok((crypto::ecdsa_raw_to_der(&raw)?, SignatureFormat::Der))
        }
        _ => Ok((raw, SignatureFormat::Raw)),
    }
}

pub async fn sign(
    State(state): State<AppState>,
    body: Result<Json<SignRequest>, JsonRejection>,
) -> Result<Json<SignResponse>, ApiError> {
    let Json(req) = body?;
    validate_key_id(&req.key_id)?;
    let payload = b64_decode("payload", &req.payload)?;

    let started = Instant::now();
    let result = state
        .backend
        .sign(&req.key_id, req.algorithm, &payload)
        .await;
    let outcome = if result.is_ok() { "ok" } else { "error" };
    metrics::counter!("sign_requests_total", "algorithm" => req.algorithm.as_str(), "outcome" => outcome).increment(1);
    let raw = result?;
    let duration = started.elapsed();

    let (signature, signature_format) = encode_signature(req.algorithm, req.signature_format, raw)?;
    tracing::info!(
        key_id = %req.key_id,
        algorithm = %req.algorithm,
        payload_bytes = payload.len(),
        signature_bytes = signature.len(),
        duration_ms = ms(duration),
        "signed"
    );
    Ok(Json(SignResponse {
        key_id: req.key_id,
        algorithm: req.algorithm,
        signature: B64.encode(signature),
        signature_format,
        duration_ms: ms(duration),
    }))
}

pub async fn verify(
    State(state): State<AppState>,
    body: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let Json(req) = body?;
    validate_key_id(&req.key_id)?;
    let payload = b64_decode("payload", &req.payload)?;
    let signature = b64_decode("signature", &req.signature)?;
    let started = Instant::now();

    let raw_signature = match (req.algorithm, req.signature_format) {
        (SigningAlgorithm::EcdsaP256Sha256, SignatureFormat::Der) => {
            match crypto::ecdsa_der_to_raw(&signature) {
                Ok(raw) => raw,
                Err(_) => {
                    return Ok(Json(VerifyResponse {
                        key_id: req.key_id,
                        algorithm: req.algorithm,
                        valid: false,
                        duration_ms: ms(started.elapsed()),
                    }))
                }
            }
        }
        _ => signature,
    };

    let public = state.backend.public_key(&req.key_id).await?;
    if public.kind() != req.algorithm.key_kind() {
        return Err(HsmError::AlgorithmMismatch {
            key_id: req.key_id,
            algorithm: req.algorithm.to_string(),
            kind: public.kind().to_string(),
        }
        .into());
    }
    let valid = crypto::verify(&public, req.algorithm, &payload, &raw_signature)?;
    let duration = started.elapsed();
    tracing::info!(key_id = %req.key_id, algorithm = %req.algorithm, valid, duration_ms = ms(duration), "verified");
    Ok(Json(VerifyResponse {
        key_id: req.key_id,
        algorithm: req.algorithm,
        valid,
        duration_ms: ms(duration),
    }))
}

pub async fn encrypt(
    State(state): State<AppState>,
    body: Result<Json<EncryptRequest>, JsonRejection>,
) -> Result<Json<EncryptResponse>, ApiError> {
    let Json(req) = body?;
    validate_key_id(&req.key_id)?;
    let plaintext = b64_decode("plaintext", &req.plaintext)?;
    let aad = b64_decode_opt("aad", &req.aad)?;
    let started = Instant::now();
    let ct = state.backend.encrypt(&req.key_id, &plaintext, &aad).await?;
    let duration = started.elapsed();
    tracing::info!(key_id = %req.key_id, plaintext_bytes = plaintext.len(), aad_bytes = aad.len(), duration_ms = ms(duration), "encrypted");
    Ok(Json(EncryptResponse {
        key_id: req.key_id,
        algorithm: AES_GCM,
        iv: B64.encode(ct.iv),
        ciphertext: B64.encode(ct.data),
        duration_ms: ms(duration),
    }))
}

pub async fn decrypt(
    State(state): State<AppState>,
    body: Result<Json<DecryptRequest>, JsonRejection>,
) -> Result<Json<DecryptResponse>, ApiError> {
    let Json(req) = body?;
    validate_key_id(&req.key_id)?;
    let iv = b64_decode("iv", &req.iv)?;
    let ciphertext = b64_decode("ciphertext", &req.ciphertext)?;
    let aad = b64_decode_opt("aad", &req.aad)?;
    let started = Instant::now();
    let plaintext = state
        .backend
        .decrypt(&req.key_id, &iv, &ciphertext, &aad)
        .await?;
    let duration = started.elapsed();
    tracing::info!(key_id = %req.key_id, ciphertext_bytes = ciphertext.len(), duration_ms = ms(duration), "decrypted");
    Ok(Json(DecryptResponse {
        key_id: req.key_id,
        plaintext: B64.encode(plaintext),
        duration_ms: ms(duration),
    }))
}

pub async fn list_keys(State(state): State<AppState>) -> Result<Json<KeysResponse>, ApiError> {
    let keys = state.backend.list_keys().await?;
    Ok(Json(KeysResponse { keys }))
}

pub async fn public_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    validate_key_id(&key_id)?;
    let public = state.backend.public_key(&key_id).await?;
    let kind = public.kind();
    Ok(Json(PublicKeyResponse {
        key_id,
        kind,
        algorithms: kind.algorithms().to_vec(),
        public_key_pem: crypto::public_key_pem(&public)?,
    }))
}

pub async fn wrap_roundtrip(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<WrapRoundtripResponse>, ApiError> {
    validate_key_id(&key_id)?;
    let report = state.backend.wrap_roundtrip(&key_id).await?;
    tracing::info!(kek_id = %key_id, roundtrip_ok = report.roundtrip_ok, "wrap roundtrip executed");
    Ok(Json(report))
}

pub async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_s: state.started.elapsed().as_secs(),
    })
}

/// Ready when the backend answers a cheap probe. A saturated pool (`Busy`)
/// still counts as ready: the token is up, it is just busy.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let pool = state.backend.pool_stats();
    let backend = state.backend.name();
    match state.backend.health().await {
        Ok(()) | Err(HsmError::Busy(_)) => Json(ReadyResponse {
            status: "ready",
            backend,
            pool,
            error: None,
        })
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse {
                    status: "not_ready",
                    backend,
                    pool,
                    error: Some(e.code()),
                }),
            )
                .into_response()
        }
    }
}

pub async fn metrics(State(state): State<AppState>) -> Response {
    let pool = state.backend.pool_stats();
    metrics::gauge!("hsm_pool_capacity").set(pool.capacity as f64);
    metrics::gauge!("hsm_pool_in_use").set(pool.in_use as f64);
    metrics::gauge!("hsm_pool_waiters").set(pool.waiters as f64);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render(),
    )
        .into_response()
}
