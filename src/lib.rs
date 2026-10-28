//! HSM-backed signing and key-management service.
//!
//! Module map:
//!
//! * [`hsm`]: the `KeyBackend` trait, the PKCS#11 and mock implementations and
//!   the bounded session pool.
//! * [`crypto`]: software-side helpers (hashing, signature encoding, public-key
//!   export, signature verification); never touches private keys.
//! * [`api`]: the Axum HTTP API and its error mapping.
//! * [`telemetry`]: structured logging, Prometheus metrics, OpenTelemetry tracing.
//! * [`config`]: CLI/environment configuration.
//! * [`error`]: the shared `HsmError` type.

pub mod api;
pub mod config;
pub mod crypto;
pub mod error;
pub mod hsm;
pub mod telemetry;
