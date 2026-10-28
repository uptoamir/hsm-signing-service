//! Axum HTTP API.
//!
//! Middleware stack (outermost first): request-id generation, tracing span,
//! request-id propagation to the response, panic catching, request timeout,
//! body size limit, HTTP metrics. Handlers only ever see decoded, size-bounded
//! input and return either a typed response or an [`ApiError`].

pub mod dto;
mod error;
mod handlers;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{MatchedPath, Request};
use axum::http::header::HeaderName;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultOnResponse, TraceLayer};
use tracing::Level;

pub use error::ApiError;

use crate::hsm::KeyBackend;

pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Clone)]
pub struct AppState {
    pub backend: Arc<dyn KeyBackend>,
    pub metrics: PrometheusHandle,
    pub started: Instant,
}

#[derive(Debug, Clone)]
pub struct ApiOptions {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
}

pub fn router(state: AppState, opts: &ApiOptions) -> Router {
    Router::new()
        .route("/v1/sign", post(handlers::sign))
        .route("/v1/verify", post(handlers::verify))
        .route("/v1/encrypt", post(handlers::encrypt))
        .route("/v1/decrypt", post(handlers::decrypt))
        .route("/v1/keys", get(handlers::list_keys))
        .route("/v1/keys/{key_id}/public", get(handlers::public_key))
        .route(
            "/v1/keys/{key_id}/wrap-roundtrip",
            post(handlers::wrap_roundtrip),
        )
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .route("/metrics", get(handlers::metrics))
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::new(REQUEST_ID_HEADER, MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(make_span)
                        .on_response(DefaultOnResponse::new().level(Level::INFO)),
                )
                .layer(PropagateRequestIdLayer::new(REQUEST_ID_HEADER))
                .layer(CatchPanicLayer::new())
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::REQUEST_TIMEOUT,
                    opts.request_timeout,
                ))
                .layer(RequestBodyLimitLayer::new(opts.max_body_bytes)),
        )
        // Separate `Router::layer` call: axum normalises the body type between
        // router layers, and this one must observe the final status of every
        // response, including 408/413 produced by the stack above.
        .layer(middleware::from_fn(http_metrics))
        .with_state(state)
}

/// One span per request. Only method, path and request id: never headers,
/// query strings or bodies.
fn make_span(req: &Request<Body>) -> tracing::Span {
    let request_id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");
    tracing::info_span!(
        "http_request",
        method = %req.method(),
        path = %req.uri().path(),
        request_id = %request_id,
    )
}

async fn http_metrics(req: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().to_string();
    // The matched route template (e.g. `/v1/keys/{key_id}/public`) keeps
    // label cardinality bounded regardless of key ids.
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());
    let response = next.run(req).await;
    let status = response.status().as_u16().to_string();
    metrics::counter!("http_requests_total", "method" => method.clone(), "route" => route.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "route" => route)
        .record(started.elapsed().as_secs_f64());
    response
}
