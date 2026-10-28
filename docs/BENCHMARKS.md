# Benchmark results

Workload: `POST /v1/sign`, ECDSA P-256 over a 256-byte payload, DER output.
Generator: `hsm-bench` (closed loop, one in-flight request per client,
HdrHistogram with 3 significant digits, latencies of successful requests
only). Each level: 2 s warm-up, then the stated measurement window.

Machine: Apple M3 Pro, 12 cores, macOS; SoftHSM2 2.7.0 (OpenSSL backend);
release build; generator and service on the same host. Raw output for every run
is in `bench-results/`.

## Native, default configuration (8 sessions, 2 s acquire timeout), 10 s per level

| conc. | requests | req/s | p50 ms | p95 ms | p99 ms | max ms | mean ms | errors |
|------:|---------:|------:|-------:|-------:|-------:|-------:|--------:|-------:|
| 1 | 92,478 | 9,248 | 0.11 | 0.12 | 0.13 | 4.16 | 0.11 | 0 |
| 10 | 317,519 | 31,751 | 0.30 | 0.49 | 0.62 | 5.48 | 0.31 | 0 |
| 100 | 309,684 | 30,958 | 3.14 | 3.84 | 4.90 | 33.76 | 3.22 | 0 |
| 500 | 305,660 | 30,511 | 15.68 | 19.63 | 30.85 | 79.94 | 16.35 | 0 |

## Native variants, 8 s per level

### 2 sessions

| conc. | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|------:|------:|-------:|-------:|-------:|-------:|-------:|
| 10 | 24,153 | 0.40 | 0.44 | 0.57 | 22.72 | 0 |
| 100 | 24,379 | 4.07 | 4.21 | 5.13 | 11.32 | 0 |
| 500 | 24,344 | 20.46 | 20.77 | 25.15 | 28.59 | 0 |

### 2 sessions, 5 ms acquire timeout (load shedding)

| conc. | req/s (ok) | p50 ms | p95 ms | p99 ms | errors | breakdown |
|------:|-----------:|-------:|-------:|-------:|-------:|-----------|
| 10 | 25,095 | 0.39 | 0.43 | 0.47 | 0 % | 200: 200,768 |
| 100 | 24,598 | 4.00 | 4.14 | 4.40 | 0.48 % | 200: 196,890 · 503: 949 |
| 500 | 8,821 | 7.46 | 9.06 | 12.20 | 87.24 % | 200: 70,670 · 503: 483,095 |

### 32 sessions

| conc. | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|------:|------:|-------:|-------:|-------:|-------:|-------:|
| 10 | 33,684 | 0.29 | 0.48 | 0.62 | 1.31 | 0 |
| 100 | 33,399 | 2.95 | 4.16 | 5.22 | 9.50 | 0 |
| 500 | 33,150 | 14.86 | 16.88 | 19.30 | 42.02 | 0 |

### Mock backend (same HTTP path, no PKCS#11 call), 8 "sessions"

| conc. | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|------:|------:|-------:|-------:|-------:|-------:|-------:|
| 10 | 43,202 | 0.21 | 0.37 | 0.41 | 10.48 | 0 |
| 100 | 49,008 | 2.02 | 2.27 | 2.53 | 27.92 | 0 |
| 500 | 49,114 | 10.29 | 10.92 | 11.66 | 18.11 | 0 |

## Inside Docker (compose `bench` profile, 8 sessions), 8 s per level

Generator and service both inside the Docker Desktop VM (`docker compose
--profile bench run --rm bench`), Debian bookworm image, SoftHSM2 2.6.1:

| conc. | requests | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|------:|---------:|------:|-------:|-------:|-------:|-------:|-------:|
| 1 | 51,060 | 6,382 | 0.15 | 0.17 | 0.21 | 1.52 | 0 |
| 10 | 231,651 | 28,955 | 0.32 | 0.60 | 0.77 | 75.26 | 0 |
| 100 | 220,725 | 27,554 | 3.35 | 4.81 | 7.94 | 67.90 | 0 |
| 500 | 217,862 | 27,149 | 17.33 | 24.03 | 30.53 | 57.95 | 0 |

About 10 % below native at saturation (VM overhead and the Debian package's
older SoftHSM2 build), same shape: flat throughput from 10 clients up, linear
latency growth, zero errors.

## Analysis

1. **Saturation point.** One client reaches 9.2k/s with a 0.11 ms round trip
   (HTTP parse + base64 + SHA-256 + `C_FindObjects` from cache + `C_Sign` +
   DER encode). Ten clients saturate the service at ~31k/s. From there to
   500 clients throughput is flat and latency grows linearly: with a closed
   loop, p50 ≈ clients ÷ throughput (500 ÷ 31k ≈ 16 ms measured 15.7 ms).
   The extra latency is time spent waiting for a semaphore permit
   (`hsm_pool_wait_seconds`), not time inside the token.
2. **What limits the 8-session configuration is CPU.** Going to 32 sessions
   adds 7 %, and the mock backend, which performs identical HTTP work without
   any PKCS#11 call, reaches 49k/s. SoftHSM2 is software: each P-256
   signature costs a core roughly 80 µs of EC arithmetic plus the module's
   own locking, and the generator competes for the same 12 cores. On a real
   HSM this ceiling moves: the token answers in 1-10 ms, so 8 sessions would
   cap throughput at roughly 1-8k/s and the queue would form at ten clients,
   not a hundred.
3. **With 2 sessions the pool is the limit** (24k/s ≈ 12k/s per session) and
   tail latency at 500 clients is the queue depth times the service time.
   This is the regime to expect in production and the reason the pool size
   must be derived from the partition's session limit and the measured
   per-operation latency, not guessed.
4. **Backpressure is a latency feature, not just an error path.** With a
   5 ms acquire timeout the service sheds 87 % of a 500-client flood as
   immediate `503 + Retry-After` responses, and the accepted requests keep a
   p99 of 12 ms instead of 25 ms. Clients that honour `Retry-After` turn the
   flood into a controlled rate; clients that do not are the ones being
   rejected.
5. **Error rate was 0 % in every non-shedding run**, including 500 concurrent
   connections, and `hsm_sessions_recycled_total` stayed at 0: no session was
   ever invalidated by SoftHSM2 under load.
6. **Not measured here, but expected to dominate with a network HSM:**
   TLS and TCP round trips to the partition, HA-group failover pauses, and
   the per-partition session cap, which makes the number of service replicas
   times `HSM_SESSIONS` the real capacity planning number.
