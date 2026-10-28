//! Structured logging, Prometheus metrics and optional OpenTelemetry tracing.
//!
//! Logging policy: events carry identifiers, sizes, durations and outcome
//! codes only. PINs, key material, payloads, plaintexts and signatures are
//! never logged. The PIN is held in a `SecretString`, whose `Debug` output is
//! redacted, so it cannot leak through a careless `{:?}` either.

use std::sync::OnceLock;
use std::time::Duration;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::LogFormat;

pub const SERVICE_NAME: &str = "hsm-signer";

/// Latency buckets (seconds) shared by all duration histograms: fine enough
/// to see sub-millisecond SoftHSM operations and coarse enough for a network
/// HSM.
const LATENCY_BUCKETS: [f64; 16] = [
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
    5.0, 10.0,
];

/// Keeps the tracer provider alive and flushes it on shutdown.
pub struct Telemetry {
    provider: Option<SdkTracerProvider>,
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("opentelemetry shutdown failed: {e}");
            }
        }
    }
}

/// Installs the global `tracing` subscriber. Tracing export is enabled only
/// when an OTLP endpoint is configured.
pub fn init(format: LogFormat, otlp_endpoint: Option<&str>) -> anyhow::Result<Telemetry> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,hyper=warn,h2=warn,tower_http=info"));

    let (otel_layer, provider) = match otlp_endpoint {
        Some(endpoint) => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(traces_url(endpoint))
                .build()?;
            let provider = SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(Resource::builder().with_service_name(SERVICE_NAME).build())
                .build();
            let tracer = provider.tracer(SERVICE_NAME);
            (
                Some(tracing_opentelemetry::layer().with_tracer(tracer)),
                Some(provider),
            )
        }
        None => (None, None),
    };

    // Logs go to stderr so that subcommands (`keys`, `self-test`) can print
    // clean JSON reports on stdout.
    let fmt_layer = match format {
        LogFormat::Json => tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(false)
            .boxed(),
        LogFormat::Pretty => tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .pretty()
            .boxed(),
        LogFormat::Compact => tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .compact()
            .boxed(),
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()?;

    if let Some(endpoint) = otlp_endpoint {
        tracing::info!(endpoint = %traces_url(endpoint), "OpenTelemetry trace export enabled");
    }
    Ok(Telemetry { provider })
}

fn traces_url(endpoint: &str) -> String {
    if endpoint.ends_with("/v1/traces") {
        endpoint.to_string()
    } else {
        format!("{}/v1/traces", endpoint.trim_end_matches('/'))
    }
}

static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();

/// Installs the Prometheus recorder once per process and returns a handle
/// for rendering `/metrics`.
pub fn metrics_handle() -> PrometheusHandle {
    METRICS
        .get_or_init(|| {
            let handle = PrometheusBuilder::new()
                .set_buckets_for_metric(
                    Matcher::Suffix("_duration_seconds".into()),
                    &LATENCY_BUCKETS,
                )
                .expect("valid histogram buckets")
                .set_buckets_for_metric(
                    Matcher::Full("hsm_pool_wait_seconds".into()),
                    &LATENCY_BUCKETS,
                )
                .expect("valid histogram buckets")
                .install_recorder()
                .expect("install Prometheus recorder");
            describe_metrics();
            handle
        })
        .clone()
}

/// Periodically drains histogram buffers so memory stays bounded between scrapes.
pub fn spawn_metrics_upkeep(handle: PrometheusHandle) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            handle.run_upkeep();
        }
    });
}

fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_histogram!(
        "hsm_operation_duration_seconds",
        Unit::Seconds,
        "Latency of individual PKCS#11 operations, by op and outcome"
    );
    describe_counter!(
        "hsm_operations_total",
        "PKCS#11 operations, by op and outcome"
    );
    describe_counter!(
        "hsm_operation_timeouts_total",
        "PKCS#11 operations abandoned after op_timeout"
    );
    describe_histogram!(
        "hsm_pool_wait_seconds",
        Unit::Seconds,
        "Time spent waiting for a pooled HSM session"
    );
    describe_counter!(
        "hsm_pool_acquire_timeouts_total",
        "Requests rejected because no HSM session became free in time (backpressure)"
    );
    describe_counter!(
        "hsm_sessions_recycled_total",
        "HSM sessions closed after an invalidating error"
    );
    describe_gauge!("hsm_pool_capacity", "Configured number of HSM sessions");
    describe_gauge!(
        "hsm_pool_in_use",
        "HSM sessions currently executing an operation"
    );
    describe_gauge!(
        "hsm_pool_waiters",
        "Requests currently waiting for an HSM session"
    );
    describe_histogram!(
        "http_request_duration_seconds",
        Unit::Seconds,
        "End-to-end HTTP request latency, by route"
    );
    describe_counter!(
        "http_requests_total",
        "HTTP requests, by method, route and status"
    );
    describe_counter!(
        "sign_requests_total",
        "Signing requests, by algorithm and outcome"
    );
}
