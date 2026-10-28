use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use hsm_signer::api::{self, ApiOptions, AppState};
use hsm_signer::config::{load_user_pin, BackendKind, Cli, Command, Config};
use hsm_signer::hsm::mock::MockBackend;
use hsm_signer::hsm::pkcs11::{Pkcs11Backend, Pkcs11Config};
use hsm_signer::hsm::pool::PoolOptions;
use hsm_signer::hsm::{KeyBackend, KeyInfo, KeysConfig};
use hsm_signer::{crypto, telemetry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let _telemetry = telemetry::init(cli.config.log_format, cli.config.otlp_endpoint.as_deref())?;
    let command = cli.command.unwrap_or(Command::Serve);
    let result = run(command, cli.config).await;
    if let Err(e) = &result {
        tracing::error!(error = format!("{e:#}"), "fatal");
    }
    result
}

async fn run(command: Command, cfg: Config) -> anyhow::Result<()> {
    match command {
        Command::Serve => serve(cfg).await,
        Command::Provision => {
            let (_, infos) = build_backend(&cfg).await?;
            println!("{}", serde_json::to_string_pretty(&infos)?);
            Ok(())
        }
        Command::Keys => {
            let (backend, _) = build_backend(&cfg).await?;
            let keys = backend.list_keys().await?;
            println!("{}", serde_json::to_string_pretty(&keys)?);
            Ok(())
        }
        Command::SelfTest => self_test(cfg).await,
    }
}

/// Connects to the configured backend and provisions the configured keys.
async fn build_backend(cfg: &Config) -> anyhow::Result<(Arc<dyn KeyBackend>, Vec<KeyInfo>)> {
    let keys = KeysConfig::load_or_default(&cfg.keys_config)?;
    let backend: Arc<dyn KeyBackend> = match cfg.backend {
        BackendKind::Pkcs11 => {
            let pin = load_user_pin(cfg)?;
            let p11 = Pkcs11Config {
                module: cfg.pkcs11_module.clone(),
                token_label: cfg.token_label.clone(),
                pool: PoolOptions {
                    capacity: cfg.sessions,
                    acquire_timeout: cfg.acquire_timeout,
                    op_timeout: cfg.op_timeout,
                },
            };
            // Loading the module and opening sessions are blocking FFI calls.
            let backend =
                tokio::task::spawn_blocking(move || Pkcs11Backend::connect(&p11, pin)).await??;
            Arc::new(backend)
        }
        BackendKind::Mock => {
            tracing::warn!("using the MOCK backend: keys are software keys held in process memory");
            Arc::new(MockBackend::new(
                cfg.mock_latency,
                cfg.sessions,
                cfg.acquire_timeout,
            ))
        }
    };
    let infos = backend.provision(&keys.keys).await?;
    for k in &infos {
        tracing::info!(
            key_id = %k.key_id,
            kind = %k.kind,
            sensitive = k.sensitive,
            extractable = k.extractable,
            never_extractable = k.never_extractable,
            local = k.local,
            "key ready"
        );
    }
    Ok((backend, infos))
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let (backend, _) = build_backend(&cfg).await?;
    let metrics = telemetry::metrics_handle();
    telemetry::spawn_metrics_upkeep(metrics.clone());
    let state = AppState {
        backend,
        metrics,
        started: Instant::now(),
    };
    let app = api::router(
        state,
        &ApiOptions {
            max_body_bytes: cfg.max_body_bytes,
            request_timeout: cfg.request_timeout,
        },
    );
    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(addr = %cfg.listen, backend = ?cfg.backend, sessions = cfg.sessions, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received; draining connections");
}

/// Runs every operation the API offers against each provisioned key and
/// prints a JSON report. Useful as a smoke test inside the container.
async fn self_test(cfg: Config) -> anyhow::Result<()> {
    let (backend, infos) = build_backend(&cfg).await?;
    let mut report = serde_json::Map::new();
    let payload = b"self-test payload";
    for info in &infos {
        let mut entry = serde_json::Map::new();
        entry.insert("kind".into(), serde_json::json!(info.kind));
        entry.insert("extractable".into(), serde_json::json!(info.extractable));
        entry.insert("sensitive".into(), serde_json::json!(info.sensitive));
        if info.kind.is_symmetric() {
            let ct = backend.encrypt(&info.key_id, payload, b"aad").await?;
            let pt = backend
                .decrypt(&info.key_id, &ct.iv, &ct.data, b"aad")
                .await?;
            entry.insert(
                "aes_gcm_roundtrip_ok".into(),
                serde_json::json!(pt == payload),
            );
            let mut tampered = ct.data.clone();
            tampered[0] ^= 1;
            let rejected = backend
                .decrypt(&info.key_id, &ct.iv, &tampered, b"aad")
                .await
                .is_err();
            entry.insert(
                "aes_gcm_tamper_rejected".into(),
                serde_json::json!(rejected),
            );
            let wrap = backend.wrap_roundtrip(&info.key_id).await?;
            entry.insert("wrap_roundtrip".into(), serde_json::to_value(&wrap)?);
        } else {
            let public = backend.public_key(&info.key_id).await?;
            for alg in &info.algorithms {
                let started = Instant::now();
                let sig = backend.sign(&info.key_id, *alg, payload).await?;
                let sign_ms = started.elapsed().as_secs_f64() * 1000.0;
                let valid = crypto::verify(&public, *alg, payload, &sig)?;
                let forged = crypto::verify(&public, *alg, b"other payload", &sig)?;
                entry.insert(
                    alg.to_string(),
                    serde_json::json!({
                        "signature_bytes": sig.len(),
                        "sign_ms": (sign_ms * 1000.0).round() / 1000.0,
                        "verify_ok": valid,
                        "forged_rejected": !forged,
                    }),
                );
            }
            entry.insert(
                "public_key_pem".into(),
                serde_json::json!(crypto::public_key_pem(&public)?),
            );
        }
        report.insert(info.key_id.clone(), serde_json::Value::Object(entry));
    }
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
