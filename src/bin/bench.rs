//! Closed-loop load generator for `POST /v1/sign`.
//!
//! For each concurrency level it runs `concurrency` tasks that each issue
//! requests back-to-back for the configured duration, then reports
//! throughput, latency percentiles (successful requests only) and the error
//! breakdown by HTTP status. A warm-up phase precedes each measurement so
//! connection setup and first-touch costs are excluded.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "hsm-bench", about = "Load generator for the HSM signing API")]
struct Args {
    /// Base URL of the service.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    url: String,
    /// Concurrency levels to run, in order.
    #[arg(long, default_value = "1,10,100,500", value_delimiter = ',')]
    concurrency: Vec<usize>,
    /// Measurement duration per level.
    #[arg(long, default_value = "10s", value_parser = humantime::parse_duration)]
    duration: Duration,
    /// Warm-up duration per level (not measured).
    #[arg(long, default_value = "2s", value_parser = humantime::parse_duration)]
    warmup: Duration,
    #[arg(long, default_value = "arkion-intermediate-prod")]
    key_id: String,
    #[arg(long, default_value = "ECDSA_P256_SHA256")]
    algorithm: String,
    /// Size of the (synthetic) payload that is signed.
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    /// Write the results table as Markdown to this file.
    #[arg(long)]
    markdown: Option<PathBuf>,
    /// Write the raw results as JSON to this file.
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
struct LevelResult {
    concurrency: usize,
    duration_s: f64,
    requests: u64,
    ok: u64,
    errors: u64,
    error_rate: f64,
    throughput_rps: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    max_ms: f64,
    mean_ms: f64,
    status_counts: BTreeMap<String, u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(2048)
        .timeout(Duration::from_secs(30))
        .build()?;

    let payload: Vec<u8> = (0..args.payload_bytes)
        .map(|i| (i * 31 % 251) as u8)
        .collect();
    let body = Bytes::from(
        serde_json::json!({
            "key_id": args.key_id,
            "algorithm": args.algorithm,
            "payload": B64.encode(payload),
        })
        .to_string(),
    );
    let url = Arc::new(format!("{}/v1/sign", args.url.trim_end_matches('/')));

    let probe = client
        .post(url.as_str())
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await?;
    anyhow::ensure!(
        probe.status().is_success(),
        "probe request failed: {} {}",
        probe.status(),
        probe.text().await.unwrap_or_default()
    );

    let mut results = Vec::new();
    for &c in &args.concurrency {
        eprintln!(
            "concurrency {c}: warm-up {:?}, measuring {:?}",
            args.warmup, args.duration
        );
        if !args.warmup.is_zero() {
            let _ = run_level(&client, &url, &body, c, args.warmup).await;
        }
        let res = run_level(&client, &url, &body, c, args.duration).await;
        eprintln!("{}", row(&res));
        results.push(res);
    }

    let table = markdown_table(&results);
    println!("{table}");
    if let Some(path) = &args.markdown {
        std::fs::write(path, &table)?;
    }
    if let Some(path) = &args.json {
        std::fs::write(path, serde_json::to_string_pretty(&results)?)?;
    }
    Ok(())
}

async fn run_level(
    client: &reqwest::Client,
    url: &Arc<String>,
    body: &Bytes,
    concurrency: usize,
    duration: Duration,
) -> LevelResult {
    let started = Instant::now();
    let deadline = started + duration;
    let mut tasks = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let client = client.clone();
        let url = Arc::clone(url);
        let body = body.clone();
        tasks.push(tokio::spawn(async move {
            let mut hist = Histogram::<u64>::new_with_bounds(1, 120_000_000, 3).expect("histogram");
            let mut statuses: BTreeMap<String, u64> = BTreeMap::new();
            let (mut ok, mut errors) = (0u64, 0u64);
            while Instant::now() < deadline {
                let t0 = Instant::now();
                let outcome = client
                    .post(url.as_str())
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .send()
                    .await;
                match outcome {
                    Ok(resp) => {
                        let status = resp.status();
                        let _ = resp.bytes().await;
                        let micros = t0.elapsed().as_micros() as u64;
                        *statuses.entry(status.as_u16().to_string()).or_default() += 1;
                        if status.is_success() {
                            ok += 1;
                            let _ = hist.record(micros.max(1));
                        } else {
                            errors += 1;
                        }
                    }
                    Err(e) => {
                        let class = if e.is_timeout() {
                            "client_timeout"
                        } else if e.is_connect() {
                            "connect_error"
                        } else {
                            "transport_error"
                        };
                        *statuses.entry(class.to_string()).or_default() += 1;
                        errors += 1;
                    }
                }
            }
            (hist, statuses, ok, errors)
        }));
    }

    let mut hist = Histogram::<u64>::new_with_bounds(1, 120_000_000, 3).expect("histogram");
    let mut statuses: BTreeMap<String, u64> = BTreeMap::new();
    let (mut ok, mut errors) = (0u64, 0u64);
    for t in tasks {
        if let Ok((h, s, o, e)) = t.await {
            let _ = hist.add(&h);
            for (k, v) in s {
                *statuses.entry(k).or_default() += v;
            }
            ok += o;
            errors += e;
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let requests = ok + errors;
    let q = |p: f64| hist.value_at_quantile(p) as f64 / 1000.0;
    LevelResult {
        concurrency,
        duration_s: (elapsed * 100.0).round() / 100.0,
        requests,
        ok,
        errors,
        error_rate: if requests == 0 {
            0.0
        } else {
            errors as f64 / requests as f64
        },
        throughput_rps: ok as f64 / elapsed,
        p50_ms: q(0.50),
        p95_ms: q(0.95),
        p99_ms: q(0.99),
        max_ms: hist.max() as f64 / 1000.0,
        mean_ms: hist.mean() / 1000.0,
        status_counts: statuses,
    }
}

fn row(r: &LevelResult) -> String {
    let statuses = r
        .status_counts
        .iter()
        .map(|(k, v)| format!("{k}:{v}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "| {:>5} | {:>8} | {:>10.1} | {:>8.2} | {:>8.2} | {:>8.2} | {:>8.2} | {:>7} | {:>6.2}% | {} |",
        r.concurrency,
        r.requests,
        r.throughput_rps,
        r.p50_ms,
        r.p95_ms,
        r.p99_ms,
        r.max_ms,
        r.errors,
        r.error_rate * 100.0,
        statuses
    )
}

fn markdown_table(results: &[LevelResult]) -> String {
    let mut out = String::new();
    out.push_str("| conc. | requests | req/s | p50 ms | p95 ms | p99 ms | max ms | errors | error rate | statuses |\n");
    out.push_str("|------:|---------:|------:|-------:|-------:|-------:|-------:|-------:|-----------:|----------|\n");
    for r in results {
        out.push_str(&row(r));
        out.push('\n');
    }
    out
}
