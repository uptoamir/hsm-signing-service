//! Mapping from internal errors to HTTP responses.
//!
//! Clients get a status code, a stable error code and a short message. For
//! server-side failures the message is generic; the detail (including the
//! PKCS#11 return value) goes to the log, correlated by `x-request-id`.

use axum::extract::rejection::JsonRejection;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use cryptoki::error::RvError;

use super::dto::{ErrorBody, ErrorDetail};
use crate::error::HsmError;

#[derive(Debug)]
pub enum ApiError {
    Hsm(HsmError),
    BadRequest(String),
    PayloadTooLarge,
}

impl From<HsmError> for ApiError {
    fn from(e: HsmError) -> Self {
        Self::Hsm(e)
    }
}

impl From<JsonRejection> for ApiError {
    fn from(r: JsonRejection) -> Self {
        if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self::PayloadTooLarge
        } else {
            Self::BadRequest(r.body_text())
        }
    }
}

struct Mapped {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after_s: Option<u64>,
}

fn map_hsm(e: &HsmError) -> Mapped {
    let m = |status: StatusCode, code: &'static str, message: String, retry: Option<u64>| Mapped {
        status,
        code,
        message,
        retry_after_s: retry,
    };
    match e {
        HsmError::KeyNotFound(_) => m(StatusCode::NOT_FOUND, e.code(), e.to_string(), None),
        HsmError::AlgorithmMismatch { .. }
        | HsmError::UnsupportedAlgorithm(_)
        | HsmError::InvalidInput(_)
        | HsmError::DecryptFailed => m(StatusCode::BAD_REQUEST, e.code(), e.to_string(), None),
        HsmError::Busy(_) => m(
            StatusCode::SERVICE_UNAVAILABLE,
            e.code(),
            "no HSM session available; retry later".into(),
            Some(1),
        ),
        HsmError::Timeout(_) => m(
            StatusCode::GATEWAY_TIMEOUT,
            e.code(),
            "HSM operation timed out".into(),
            Some(1),
        ),
        HsmError::Unavailable(_) => m(
            StatusCode::SERVICE_UNAVAILABLE,
            e.code(),
            "HSM unavailable".into(),
            Some(5),
        ),
        HsmError::Pkcs11(_) => match e.rv() {
            Some(
                RvError::DataLenRange
                | RvError::DataInvalid
                | RvError::ArgumentsBad
                | RvError::SignatureLenRange
                | RvError::KeyFunctionNotPermitted
                | RvError::KeyTypeInconsistent,
            ) => m(
                StatusCode::BAD_REQUEST,
                "INVALID_INPUT",
                "input rejected by the token".into(),
                None,
            ),
            Some(
                RvError::MechanismInvalid
                | RvError::MechanismParamInvalid
                | RvError::FunctionNotSupported,
            ) => m(
                StatusCode::NOT_IMPLEMENTED,
                "UNSUPPORTED",
                "operation not supported by the token".into(),
                None,
            ),
            _ if e.invalidates_session() => m(
                StatusCode::SERVICE_UNAVAILABLE,
                "HSM_ERROR",
                "HSM session error; the session was recycled, retry".into(),
                Some(1),
            ),
            _ => m(
                StatusCode::INTERNAL_SERVER_ERROR,
                "HSM_ERROR",
                "HSM operation failed".into(),
                None,
            ),
        },
        HsmError::Internal(_) => m(
            StatusCode::INTERNAL_SERVER_ERROR,
            e.code(),
            "internal error".into(),
            None,
        ),
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (mapped, detail) = match &self {
            ApiError::BadRequest(msg) => (
                Mapped {
                    status: StatusCode::BAD_REQUEST,
                    code: "INVALID_INPUT",
                    message: msg.clone(),
                    retry_after_s: None,
                },
                msg.clone(),
            ),
            ApiError::PayloadTooLarge => (
                Mapped {
                    status: StatusCode::PAYLOAD_TOO_LARGE,
                    code: "PAYLOAD_TOO_LARGE",
                    message: "request body exceeds the configured limit".into(),
                    retry_after_s: None,
                },
                "payload too large".into(),
            ),
            ApiError::Hsm(e) => (map_hsm(e), e.to_string()),
        };

        if mapped.status.is_server_error() {
            tracing::error!(code = mapped.code, status = mapped.status.as_u16(), error = %detail, "request failed");
        } else {
            tracing::warn!(code = mapped.code, status = mapped.status.as_u16(), error = %detail, "request rejected");
        }

        let body = Json(ErrorBody {
            error: ErrorDetail {
                code: mapped.code,
                message: mapped.message,
            },
        });
        let mut response = (mapped.status, body).into_response();
        if let Some(secs) = mapped.retry_after_s {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, secs.into());
        }
        response
    }
}
