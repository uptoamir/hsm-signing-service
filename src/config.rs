//! Command-line and environment configuration.
//!
//! Secrets are deliberately *not* ordinary CLI flags: the user PIN is read
//! from a file (`HSM_USER_PIN_FILE`, e.g. a mounted Docker/Kubernetes secret)
//! or, as a fallback, from the `HSM_USER_PIN` environment variable, and is
//! held in a `SecretString` from the moment it is read.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Args, Parser, Subcommand, ValueEnum};
use cryptoki::types::AuthPin;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "hsm-signer",
    version,
    about = "HSM-backed signing and key-management service (PKCS#11)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub config: Config,
}

#[derive(Subcommand, Debug, Clone, Copy)]
pub enum Command {
    /// Run the HTTP service (default).
    Serve,
    /// Provision the keys listed in the keys config, then exit.
    Provision,
    /// Print the provisioned keys and their protection attributes as JSON.
    Keys,
    /// Exercise sign/verify, AES-GCM and key wrapping against the backend and
    /// print a JSON report.
    SelfTest,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// A real PKCS#11 token (SoftHSM2 or an HSM).
    Pkcs11,
    /// In-memory software keys; for tests and local API exploration only.
    Mock,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

#[derive(Args, Debug, Clone)]
pub struct Config {
    /// Address to bind the HTTP API to.
    #[arg(
        long,
        global = true,
        env = "LISTEN_ADDR",
        default_value = "0.0.0.0:8080"
    )]
    pub listen: SocketAddr,

    /// Key backend.
    #[arg(
        long,
        global = true,
        env = "HSM_BACKEND",
        default_value = "pkcs11",
        value_enum
    )]
    pub backend: BackendKind,

    /// Path of the PKCS#11 module.
    #[arg(long, global = true, env = "PKCS11_MODULE", default_value = default_module())]
    pub pkcs11_module: PathBuf,

    /// Label of the token to use.
    #[arg(long, global = true, env = "HSM_TOKEN_LABEL", default_value = "arkion")]
    pub token_label: String,

    /// File containing the user PIN (preferred over the HSM_USER_PIN variable).
    #[arg(long, global = true, env = "HSM_USER_PIN_FILE")]
    pub user_pin_file: Option<PathBuf>,

    /// Number of pooled PKCS#11 sessions, i.e. the maximum number of
    /// concurrent token operations.
    #[arg(long, global = true, env = "HSM_SESSIONS", default_value_t = 8)]
    pub sessions: usize,

    /// How long a request waits for a free session before being rejected
    /// with 503 (backpressure).
    #[arg(long, global = true, env = "HSM_ACQUIRE_TIMEOUT", default_value = "2s", value_parser = humantime::parse_duration)]
    pub acquire_timeout: Duration,

    /// Upper bound on a single token operation before the request fails with 504.
    #[arg(long, global = true, env = "HSM_OP_TIMEOUT", default_value = "5s", value_parser = humantime::parse_duration)]
    pub op_timeout: Duration,

    /// Overall HTTP request timeout.
    #[arg(long, global = true, env = "REQUEST_TIMEOUT", default_value = "10s", value_parser = humantime::parse_duration)]
    pub request_timeout: Duration,

    /// YAML file listing the keys to provision at startup.
    #[arg(long, global = true, env = "KEYS_CONFIG", default_value = "keys.yaml")]
    pub keys_config: PathBuf,

    /// Maximum accepted request body size in bytes.
    #[arg(
        long,
        global = true,
        env = "MAX_BODY_BYTES",
        default_value_t = 1_048_576
    )]
    pub max_body_bytes: usize,

    /// Log output format.
    #[arg(
        long,
        global = true,
        env = "LOG_FORMAT",
        default_value = "json",
        value_enum
    )]
    pub log_format: LogFormat,

    /// OTLP/HTTP collector endpoint for traces (e.g. http://otel-collector:4318).
    /// Trace export is disabled when unset.
    #[arg(long, global = true, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    pub otlp_endpoint: Option<String>,

    /// Simulated per-operation latency for the mock backend.
    #[arg(long, global = true, env = "MOCK_LATENCY", default_value = "0ms", value_parser = humantime::parse_duration)]
    pub mock_latency: Duration,
}

fn default_module() -> &'static str {
    if cfg!(target_os = "macos") {
        "/opt/homebrew/lib/softhsm/libsofthsm2.so"
    } else {
        "/usr/lib/softhsm/libsofthsm2.so"
    }
}

/// Reads the user PIN from the configured file or environment variable.
/// The PIN never appears in logs, `--help` output or process arguments.
pub fn load_user_pin(cfg: &Config) -> anyhow::Result<AuthPin> {
    if let Some(path) = &cfg.user_pin_file {
        let raw = Zeroizing::new(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading PIN file {}", path.display()))?,
        );
        let pin = raw.trim_end_matches(['\n', '\r']);
        anyhow::ensure!(!pin.is_empty(), "PIN file {} is empty", path.display());
        return Ok(AuthPin::from(pin.to_string()));
    }
    if let Ok(pin) = std::env::var("HSM_USER_PIN") {
        let pin = Zeroizing::new(pin);
        if !pin.is_empty() {
            return Ok(AuthPin::from(pin.to_string()));
        }
    }
    anyhow::bail!("no user PIN configured: set HSM_USER_PIN_FILE (preferred) or HSM_USER_PIN")
}
