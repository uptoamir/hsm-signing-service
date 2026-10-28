# hsm-signer: HSM-backed signing and key-management service

A Rust (Axum + Tokio) service that signs, verifies, encrypts and wraps with
keys that never leave a PKCS#11 token. It runs against SoftHSM2 out of the box
and against any PKCS#11-compatible HSM by changing one path.

* Non-exportable ECDSA P-256, RSA-3072 and Ed25519 signing keys and an
  AES-256 key-encryption key, all generated inside the token with
  `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`.
* `POST /v1/sign` (the required API), plus verify, AES-256-GCM encrypt/decrypt,
  key listing with protection attributes, public-key export and a key-wrap
  round trip that doubles as a non-exportability proof.
* A bounded PKCS#11 session pool with acquire timeouts, operation timeouts,
  load shedding (`503` + `Retry-After`) and session recycling.
* Structured JSON logs that never contain PINs, key material, payloads or
  signatures; Prometheus metrics; optional OpenTelemetry tracing.
* A clean `KeyBackend` trait with a PKCS#11 implementation and an in-memory
  mock, unit tests, API tests and an integration test against SoftHSM2.
* A load generator and measured results at 1, 10, 100 and 500 concurrent
  callers (section 7), and the CA-architecture answer in
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 1. Quick start

### 1.1 Docker Compose (recommended for evaluation)

Requirements: Docker with Compose v2.

```bash
# PINs are Docker secrets; they are generated once and never baked into the image.
mkdir -p secrets && openssl rand -hex 16 > secrets/user_pin.txt && openssl rand -hex 16 > secrets/so_pin.txt

docker compose up --build            # builds the image, initializes a SoftHSM2 token, provisions keys
curl -s localhost:8080/readyz        # {"status":"ready","backend":"pkcs11","pool":{...}}
```

Sign and verify:

```bash
PAYLOAD=$(printf 'hello arkion' | base64)
curl -s -X POST localhost:8080/v1/sign -H 'content-type: application/json' \
  -d "{\"key_id\":\"arkion-intermediate-prod\",\"algorithm\":\"ECDSA_P256_SHA256\",\"payload\":\"$PAYLOAD\"}"
# {"key_id":"arkion-intermediate-prod","algorithm":"ECDSA_P256_SHA256","signature":"MEQCI...","signature_format":"der","duration_ms":0.212}
```

Other useful commands:

```bash
docker compose exec hsm-signer hsm-signer self-test          # sign/verify/AES-GCM/wrap report for every key
docker compose exec hsm-signer hsm-signer keys               # key attributes as read from the token
docker compose --profile bench run --rm bench                # load test inside the compose network
docker compose down -v                                       # also removes the token volume
```

Build and run the image without Compose:

```bash
docker build -t arkion/hsm-signer:local .
docker run --rm -p 8080:8080 -e HSM_USER_PIN="$(openssl rand -hex 16)" arkion/hsm-signer:local
# or let the entrypoint generate a PIN for a throw-away container:
docker run --rm -p 8080:8080 arkion/hsm-signer:local
```

The image (Debian bookworm-slim + `softhsm2` + `opensc`, non-root user) ships
`hsm-signer` and `hsm-bench`. The entrypoint initializes the token on first
start, stores it in the `/var/lib/softhsm/tokens` volume, and `exec`s the
service. PINs come from `HSM_USER_PIN_FILE`/`HSM_SO_PIN_FILE` (secrets),
else `HSM_USER_PIN`/`HSM_SO_PIN`, else a random PIN is generated and stored
with mode 0600 beside the token (dev only).

### 1.2 Local build with SoftHSM2

Requirements: Rust 1.85+, SoftHSM2 (`brew install softhsm` or
`apt install softhsm2`), optionally OpenSC for `pkcs11-tool`.

```bash
eval "$(./scripts/dev-token.sh)"     # creates ./.softhsm/<token> once, prints SOFTHSM2_CONF, PKCS11_MODULE, HSM_USER_PIN_FILE
cargo run --release -- serve --log-format pretty
cargo run --release -- self-test     # or: keys | provision
```

`make run`, `make self-test`, `make bench`, `make test` wrap the same steps.

### 1.3 Without any token (mock backend)

```bash
cargo run --release -- --backend mock serve
```

The mock keeps software keys in process memory and simulates a session pool
(`--mock-latency 2ms` to imitate a slow HSM). It exists for tests and API
exploration; it is never a substitute for the real backend.

---

## 2. API

All binary fields are standard base64. Every response carries an
`x-request-id` header (generated or propagated) that also appears in the logs.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/sign` | Sign a payload with a token-resident key |
| `POST` | `/v1/verify` | Verify a signature with the exported public key (software) |
| `POST` | `/v1/encrypt` | AES-256-GCM encrypt inside the token, IV from the token RNG |
| `POST` | `/v1/decrypt` | AES-256-GCM decrypt inside the token |
| `GET` | `/v1/keys` | Keys and their protection attributes as read from the token |
| `GET` | `/v1/keys/{key_id}/public` | Public key as PEM `SubjectPublicKeyInfo` |
| `POST` | `/v1/keys/{key_id}/wrap-roundtrip` | Key-wrapping workflow + non-exportability proofs (section 4.5) |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Readiness: probes the token, reports pool statistics |
| `GET` | `/metrics` | Prometheus exposition |

### `POST /v1/sign`

```json
{ "key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "payload": "<base64>", "signature_format": "der" }
```

```json
{ "key_id": "arkion-intermediate-prod", "algorithm": "ECDSA_P256_SHA256", "signature": "<base64>", "signature_format": "der", "duration_ms": 0.21 }
```

| `algorithm` | Key kind | Input to the token | Signature |
|---|---|---|---|
| `ECDSA_P256_SHA256` | `ecdsa-p256` | SHA-256 digest, `CKM_ECDSA` | DER `SEQUENCE{r,s}` by default; `"signature_format":"raw"` gives `r‖s` (64 bytes) |
| `RSA_PSS_SHA256` | `rsa-3072` | SHA-256 digest, `CKM_RSA_PKCS_PSS` (MGF1-SHA256, 32-byte salt) | 384 bytes |
| `ED25519` | `ed25519` | Whole message, `CKM_EDDSA` (pure) | 64 bytes |

`duration_ms` is the time spent in the backend call (pool wait + token
operation), measured by the handler.

### `POST /v1/verify`

Same fields plus `signature`; returns `{"valid": true|false, ...}`. A
malformed signature yields `valid: false`, not an error. Verification uses
the public key exported from the token and the `p256`, `rsa` and
`ed25519-dalek` crates, so it is an independent check of what the token
produced. The integration test additionally cross-checks with `C_Verify`
inside the token.

### `POST /v1/encrypt` and `/v1/decrypt`

```json
{ "key_id": "arkion-kek-prod", "plaintext": "<base64>", "aad": "<base64, optional>" }
{ "key_id": "arkion-kek-prod", "algorithm": "AES_256_GCM", "iv": "<12 bytes>", "ciphertext": "<ciphertext‖16-byte tag>", "duration_ms": 0.09 }
```

Decryption with a wrong tag or AAD returns `400 DECRYPT_FAILED`.

### Errors

```json
{ "error": { "code": "KEY_NOT_FOUND", "message": "key not found: nope" } }
```

| Status | Code | When |
|---|---|---|
| 400 | `INVALID_INPUT`, `ALGORITHM_MISMATCH`, `UNSUPPORTED_ALGORITHM`, `DECRYPT_FAILED` | Bad base64, unknown field, wrong algorithm for the key, tag failure |
| 404 | `KEY_NOT_FOUND` | Key not provisioned |
| 413 | `PAYLOAD_TOO_LARGE` | Body above `MAX_BODY_BYTES` (1 MiB default) |
| 408 | (timeout layer) | Request exceeded `REQUEST_TIMEOUT` |
| 501 | `UNSUPPORTED` | Token lacks the mechanism |
| 503 | `HSM_BUSY` (+ `Retry-After: 1`) | No session within `HSM_ACQUIRE_TIMEOUT` (backpressure) |
| 503 | `HSM_UNAVAILABLE`, `HSM_ERROR` (+ `Retry-After`) | Token/session failure; the session was recycled |
| 504 | `HSM_TIMEOUT` | Token operation exceeded `HSM_OP_TIMEOUT` |
| 500 | `HSM_ERROR`, `INTERNAL` | Anything else; detail only in the log |

5xx messages are generic on purpose; the PKCS#11 return value is logged with
the request id.

---

## 3. Code map

```
src/
  main.rs            CLI (serve | provision | keys | self-test), backend construction, graceful shutdown
  config.rs          clap/env configuration, PIN loading (file > env, SecretString)
  error.rs           HsmError: the one error type crossing the HSM/API boundary
  hsm/mod.rs         KeyBackend trait, SigningAlgorithm, KeyKind, KeyInfo, KeySpec/keys.yaml
  hsm/pool.rs        bounded PKCS#11 session pool (semaphore + spawn_blocking + timeouts + recycling)
  hsm/pkcs11.rs      the real backend: module loading, token lookup, provisioning, sign/encrypt/wrap
  hsm/mock.rs        in-memory backend with the same semantics
  crypto.rs          SHA-256, DER<->raw ECDSA, EC point decoding, software verification, PEM export
  api/{mod,dto,handlers,error}.rs
                     Axum router + middleware stack, request/response types, status mapping
  telemetry.rs       tracing subscriber (JSON/pretty), Prometheus recorder, OTLP tracer
  bin/bench.rs       closed-loop load generator (hdrhistogram)
tests/
  api_mock.rs        HTTP behaviour against the mock (formats, errors, limits, 503 shedding)
  softhsm_integration.rs
                     everything against a throw-away SoftHSM2 token (see section 9)
docs/ARCHITECTURE.md the 100k certs/s design answer
docker/, Dockerfile, docker-compose.yml, keys.yaml, scripts/dev-token.sh
```

Request flow for `/v1/sign`:

```
HTTP -> request-id -> trace span -> timeout -> body limit -> handler
  -> decode base64, validate key_id
  -> KeyBackend::sign
       pkcs11: check key kind vs algorithm (no token call)
               hash payload (SHA-256) unless Ed25519
               pool.with_session("sign"):  wait for permit (<= acquire_timeout)
                                           spawn_blocking: checkout session
                                                           C_FindObjects (cached per session)
                                                           C_Sign
                                           op_timeout on the whole blocking call
  -> encode (DER for ECDSA) -> base64 -> JSON
```

The HTTP layer depends only on `Arc<dyn KeyBackend>`, so the PKCS#11 and
mock implementations are interchangeable at start-up (`--backend`).

---

## 4. HSM and key-management approach

### 4.1 Module, token and authentication

* The PKCS#11 module path (`PKCS11_MODULE`) and token label
  (`HSM_TOKEN_LABEL`) are configuration; the token is found by label among
  the initialized slots, never by slot number (slot ids are not stable).
* The module is loaded **once per process and never unloaded**. `C_Initialize`
  is per process, and PKCS#11 modules (SoftHSM2 through OpenSSL included)
  register thread-local destructors that make `dlclose` unsafe. The
  integration test found this the hard way: dropping the last context crashed
  exiting threads.
* `C_Initialize` is called with `CKF_OS_LOCKING_OK` so different sessions can
  be driven from different threads.
* The user PIN is read from `HSM_USER_PIN_FILE` (a mounted secret, preferred)
  or `HSM_USER_PIN`, wrapped in a `SecretString` immediately (its `Debug`
  output is redacted) and passed to `C_Login`. It is never a CLI flag, never
  logged and never part of `--help` output. The SO PIN is only used by the
  entrypoint to initialize the token and is removed from the service's
  environment before `exec`.
* Login is per token per application: once the first pooled session logs in,
  the others are logged in too; `CKR_USER_ALREADY_LOGGED_IN` is treated as
  success.

### 4.2 Provisioning

`keys.yaml` declares the keys the service must have:

```yaml
keys:
  - { id: arkion-intermediate-prod, kind: ecdsa-p256 }
  - { id: arkion-kek-prod,          kind: aes-256 }
  - { id: arkion-rsa-prod,          kind: rsa-3072, optional: true }
  - { id: arkion-ed25519-prod,      kind: ed25519,  optional: true }
```

At start-up (and with `hsm-signer provision`) each key is looked up by
`CKA_LABEL`; if absent it is generated inside the token (`C_GenerateKey` /
`C_GenerateKeyPair`) with:

| Attribute | Private / secret keys | Public keys |
|---|---|---|
| `CKA_TOKEN` | true (persistent) | true |
| `CKA_PRIVATE` | true (login required) | false |
| `CKA_SENSITIVE` | **true** (value never readable) | n/a |
| `CKA_EXTRACTABLE` | **false** (never wrappable out) | n/a |
| `CKA_SIGN` / `CKA_ENCRYPT`,`DECRYPT`,`WRAP`,`UNWRAP` | per kind | `CKA_VERIFY` |
| `CKA_LABEL`, `CKA_ID` | the key id | the key id |

After provisioning the attributes are read back; a key that is extractable or
not sensitive is refused even if it carries the right label. `GET /v1/keys`
exposes exactly these attributes (`sensitive`, `extractable`,
`never_extractable`, `local`, `token_object`). Only keys listed in
`keys.yaml` are reachable through the API, whatever else is on the token.
`optional: true` keys are skipped with a warning if the token lacks the
mechanism (for example an HSM without EdDSA).

### 4.3 Locating keys

Objects are found with a `CKA_CLASS` + `CKA_LABEL` template. Two objects with
the same label are an error, never an arbitrary pick. Handles are cached per
session because PKCS#11 does not guarantee handle validity across sessions.

### 4.4 Hashing and signature encoding

For ECDSA and RSA-PSS the service hashes with SHA-256 and sends the digest to
the token (`CKM_ECDSA`, `CKM_RSA_PKCS_PSS`). The digest is not secret, the
private key is used only inside the token either way, and the token round trip
stays independent of payload size. Ed25519 is a pure scheme and receives the
whole message. PKCS#11 returns ECDSA signatures as fixed-width `r‖s`; the API
converts to DER by default because that is what X.509 and TLS consume.

### 4.5 Symmetric key, AES-GCM and key wrapping

`arkion-kek-prod` is an AES-256 key generated in the token. Two operations
use it:

* **AES-256-GCM** (`/v1/encrypt`, `/v1/decrypt`): the 12-byte IV is produced by
  the token's RNG (`C_GenerateRandom`), the tag is 128 bits, AAD is optional.
  Plaintext and key never meet outside the token.
* **Key wrapping** (`POST /v1/keys/arkion-kek-prod/wrap-roundtrip`), the
  workflow a CA would use to move a short-lived issuing key around:

  1. generate an ephemeral, *extractable* AES data-encryption key (DEK) as a
     session object and encrypt a sample under it;
  2. wrap the DEK under the KEK with `CKM_AES_KEY_WRAP_PAD` (RFC 5649) -- the
     only form in which the DEK ever leaves the token (40 bytes for a 32-byte
     key);
  3. destroy the original DEK;
  4. unwrap the blob into a new, non-extractable session key;
  5. decrypt the sample under the unwrapped copy;
  6. ask the token to wrap the KEK itself and to reveal its `CKA_VALUE`.

  Steps 1-5 prove the mechanism works; step 6 records the token's refusals:

  ```json
  {"kek_id":"arkion-kek-prod","wrap_mechanism":"CKM_AES_KEY_WRAP_PAD","wrapped_key_len":40,"roundtrip_ok":true,
   "kek_wrap_attempt":"rejected: KeyUnextractable","kek_value_read_attempt":"rejected: CKR_ATTRIBUTE_SENSITIVE"}
  ```

  Those two refusals (`CKR_KEY_UNEXTRACTABLE`, `CKR_ATTRIBUTE_SENSITIVE`) are
  the token's own statement that the KEK cannot leave the boundary.

### 4.6 What never leaves the boundary

Private and secret key material is never returned by any `KeyBackend`
method, never serialized and never logged. The code paths that could touch it
do not exist: there is no `CKA_VALUE` read for private/secret keys anywhere
except the deliberate negative proof above, and the only wrap call targets
ephemeral, explicitly extractable session keys.

---

## 5. Concurrency and session management

PKCS#11 sessions are scarce (tokens cap them), stateful (login, active
operations) and synchronous. `hsm/pool.rs` treats them accordingly:

| Concern | Mechanism | Setting |
|---|---|---|
| Bounded concurrency | `tokio::sync::Semaphore` with one permit per session; at most `capacity` token calls in flight | `HSM_SESSIONS` (default 8) |
| Backpressure | A request waits at most `acquire_timeout` for a permit, then fails fast with `503 HSM_BUSY` + `Retry-After: 1` | `HSM_ACQUIRE_TIMEOUT` (2 s) |
| Non-blocking runtime | Every token call runs in `spawn_blocking`; the async workers never block on FFI | – |
| Operation timeout | The caller stops waiting after `op_timeout` (`504 HSM_TIMEOUT`). A blocking FFI call cannot be cancelled, so the worker keeps its permit until the token answers; the bound is never violated | `HSM_OP_TIMEOUT` (5 s) |
| Session reuse | Sessions are opened eagerly at start-up (fail fast on misconfiguration, no cold-start latency) and returned to an idle list after each call | – |
| Session health | Errors such as `CKR_SESSION_HANDLE_INVALID`, `CKR_DEVICE_ERROR`, `CKR_USER_NOT_LOGGED_IN` discard the session; a replacement is opened lazily on next use | `hsm_sessions_recycled_total` |
| Request timeout | Whole-request bound at the HTTP layer (`408`) | `REQUEST_TIMEOUT` (10 s) |
| Observability | `hsm_pool_in_use`, `hsm_pool_waiters`, `hsm_pool_wait_seconds`, `hsm_pool_acquire_timeouts_total`, per-op latency histograms; `/readyz` reports the same numbers | – |

Why a semaphore + `spawn_blocking` rather than dedicated worker threads: it
keeps the pool a plain data structure, lets Tokio size the blocking thread
pool, and makes the acquire timeout a one-liner. A fixed worker-per-session
design would be the alternative for tokens whose sessions are bound to the
thread that opened them.

---

## 6. Observability

* **Logs**: `tracing` with JSON (default) or `pretty`/`compact` output; one
  span per request with method, path and `request_id`; events carry key ids,
  algorithms, byte lengths, durations and error codes. Never logged: PINs,
  key material, payloads, plaintexts, ciphertexts, signatures, request
  bodies, headers.
* **Metrics** (`/metrics`): `hsm_operation_duration_seconds{op,outcome}`,
  `hsm_operations_total`, `hsm_operation_timeouts_total`,
  `hsm_pool_{capacity,in_use,waiters}`, `hsm_pool_wait_seconds`,
  `hsm_pool_acquire_timeouts_total`, `hsm_sessions_recycled_total`,
  `http_requests_total{method,route,status}`,
  `http_request_duration_seconds{method,route}`,
  `sign_requests_total{algorithm,outcome}`. Routes are the matched templates
  (`/v1/keys/{key_id}/public`), so key ids never create label cardinality.
* **Tracing**: set `OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318` and the
  request span and the `hsm_request` spans are exported over OTLP/HTTP
  (protobuf). Disabled when unset.

---

## 7. Benchmark results

`hsm-bench` runs `concurrency` closed-loop clients for a fixed duration per
level, reports successful-request latency percentiles from an HdrHistogram
and the status breakdown. Environment: Apple M3 Pro (12 cores), macOS,
SoftHSM2 2.7.0, release build, client and server on the same machine,
`POST /v1/sign` with a 256-byte payload, ECDSA P-256, 2 s warm-up + 10 s
measurement per level.

**Default configuration (8 sessions, 2 s acquire timeout):**

| conc. | requests | req/s | p50 ms | p95 ms | p99 ms | max ms | errors |
|------:|---------:|------:|-------:|-------:|-------:|-------:|-------:|
| 1 | 92,478 | 9,248 | 0.11 | 0.12 | 0.13 | 4.16 | 0 |
| 10 | 317,519 | 31,751 | 0.30 | 0.49 | 0.62 | 5.48 | 0 |
| 100 | 309,684 | 30,958 | 3.14 | 3.84 | 4.90 | 33.76 | 0 |
| 500 | 305,660 | 30,511 | 15.68 | 19.63 | 30.85 | 79.94 | 0 |

**Variants (8 s per level):**

| configuration | conc. | req/s | p50 ms | p99 ms | errors |
|---|---:|---:|---:|---:|---|
| 2 sessions | 500 | 24,344 | 20.46 | 25.15 | 0 |
| 2 sessions, 5 ms acquire timeout | 500 | 8,821 | 7.46 | 12.20 | 87 % `503 HSM_BUSY` |
| 32 sessions | 500 | 33,150 | 14.86 | 19.30 | 0 |
| mock backend (no PKCS#11) | 500 | 49,114 | 10.29 | 11.66 | 0 |

Observations:

* **Throughput saturates at about 31k signatures/s from 10 callers upward and
  stays flat to 500.** Latency then grows linearly with concurrency
  (p50 ≈ callers / throughput: 500 / 31k ≈ 16 ms), which is queueing in the
  semaphore, not slowdown in the token: every request still spends about
  0.1 ms in SoftHSM.
* **The bottleneck at 8 sessions is CPU, not the pool.** 32 sessions add only
  7 %; the mock backend, which does the same HTTP work but no PKCS#11 call,
  tops out at 49k/s. SoftHSM2 is software, so each signature costs a core
  about 80 µs of EC arithmetic plus the FFI/locking overhead, and the load
  generator shares the 12 cores with the server.
* **With 2 sessions the pool is the bottleneck** (24k/s, i.e. ~12k/s per
  session), which is the regime a real HSM lives in: a network HSM answers in
  1-10 ms, so with 8 sessions the ceiling would be roughly 1-8k/s and the
  queue would build up at far lower concurrency.
* **Shedding works as designed.** With a 5 ms acquire timeout and 500 callers,
  87 % of requests are rejected immediately with `503` + `Retry-After`, while
  the requests that are accepted keep a p99 of 12 ms instead of 25 ms. That
  is the behaviour wanted in front of a saturated HSM: fail fast, keep the
  accepted work fast, let clients back off.
* The in-container run (`docker compose --profile bench run bench`) is
  reported in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md); numbers are lower
  under the Docker Desktop VM but the shape is identical.

Reproduce: `make bench` (local) or the compose profile. Raw results are
in `bench-results/`; `make bench` writes new runs there.

---

## 8. Architecture question

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) answers the 100,000
certificates-per-second question. In one paragraph: keep the root offline
and the intermediates in HSMs (this service is that tier), issue short-lived
per-signer *issuing CA* certificates from the intermediate (hundreds of HSM
signatures per day, not per second), and sign leaves in software with those
short-lived keys at line rate. Key lifetime, name constraints and
transparency logging bound the blast radius that key location would
otherwise have to; HSM count is driven by regions × HA, not throughput.

---

## 9. Testing

```bash
cargo test                         # unit + API (mock) + SoftHSM2 integration (auto-skips without SoftHSM2)
HSM_TEST_REQUIRE=1 cargo test      # fail instead of skipping when SoftHSM2 is missing (CI)
cargo clippy --all-targets -- -D warnings
```

* `src/crypto.rs`, `src/hsm/mod.rs`: unit tests for encodings, wire names,
  key-id validation and the shipped `keys.yaml`.
* `tests/api_mock.rs`: DER/raw signatures, Ed25519, every error path, body
  limit, AES-GCM tamper detection, key listing, public-key PEM, wrap round
  trip, health/ready/metrics, and 503 shedding under a saturated pool.
* `tests/softhsm_integration.rs` creates a fresh token in a temporary
  directory with `softhsm2-util`, then checks: attributes of all four key
  kinds, signatures verified both in software and with `C_Verify` in the
  token, forged/tampered signatures rejected, AES-GCM with fresh IVs and tag
  failures, the wrap round trip including the two refusals, 64 concurrent
  signs through a 4-session pool with no recycling, backpressure (`Busy`)
  and operation timeout on a 1-session pool with the pool usable afterwards,
  key persistence across a second connection, and the HTTP API in front of
  the real token.

---

## 10. Configuration

| Variable / flag | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` / `--listen` | `0.0.0.0:8080` | Bind address |
| `HSM_BACKEND` / `--backend` | `pkcs11` | `pkcs11` or `mock` |
| `PKCS11_MODULE` / `--pkcs11-module` | platform SoftHSM2 path | PKCS#11 module |
| `HSM_TOKEN_LABEL` / `--token-label` | `arkion` | Token label |
| `HSM_USER_PIN_FILE` | – | File with the user PIN (preferred) |
| `HSM_USER_PIN` | – | User PIN (fallback) |
| `HSM_SESSIONS` / `--sessions` | `8` | Pool size = max concurrent token operations |
| `HSM_ACQUIRE_TIMEOUT` | `2s` | Max wait for a session before `503` |
| `HSM_OP_TIMEOUT` | `5s` | Max token operation time before `504` |
| `REQUEST_TIMEOUT` | `10s` | Whole-request timeout (`408`) |
| `KEYS_CONFIG` / `--keys-config` | `keys.yaml` | Keys to provision |
| `MAX_BODY_BYTES` | `1048576` | Request body limit (`413`) |
| `LOG_FORMAT` / `--log-format` | `json` | `json`, `pretty`, `compact` |
| `RUST_LOG` | `info` | `tracing` filter |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | – | Enables OTLP/HTTP trace export |
| `MOCK_LATENCY` | `0ms` | Simulated latency for the mock backend |
| `SOFTHSM2_CONF` | – | SoftHSM2 configuration (token directory) |

---

## 11. Security considerations

* Keys are generated inside the token, sensitive and non-extractable; the
  service refuses to use keys that are not.
* PINs: file or environment only, held as `SecretString`, never logged, never
  on the command line; the SO PIN never reaches the service.
* No key material, payloads, plaintexts or signatures in logs or traces;
  request bodies are size-limited and rejected on unknown fields.
* Key ids are validated (`[A-Za-z0-9._-]{1,64}`) before being used as labels.
* 5xx responses carry generic messages; detail stays in logs keyed by request
  id.
* IVs for GCM come from the token RNG; GCM nonces are never derived from
  counters held in application state, so restarts cannot repeat one.
* The container runs as a non-root user with a read-only image and a
  dedicated volume for the token.
* Not implemented (would be required in production): client authentication
  and per-caller authorization on the API (this service should sit behind
  mTLS, e.g. the proxy from assignment 2), audit logging to an append-only
  sink, and key-usage policy (which caller may use which key).

---

## 12. Assumptions and known limitations

* One token, found by label; multi-token/multi-slot routing is out of scope.
* Keys are generated by the service if absent. In a real deployment keys are
  usually created by a ceremony and the service only *uses* them; the
  provisioning code path then becomes a check.
* The `wrap-roundtrip` endpoint is a diagnostic. It creates and destroys
  session objects on every call and is not meant for production traffic.
* `C_Finalize` is intentionally never called (section 4.1). Token state is
  flushed by SoftHSM2 on every operation; HSM client libraries that require
  `C_Finalize` for clean disconnects would need a shutdown hook that finalizes
  without unloading.
* SoftHSM2 is a software token: the measured latencies are much lower and
  the throughput much higher than a network HSM; the *shape* of the results
  (saturation, queueing, shedding) is what transfers.
* Signatures are not deterministic for ECDSA/RSA-PSS (by design); tests
  verify rather than compare bytes.
* The verify endpoint trusts the public key read from the token at request
  time; a production CA would pin public keys at provisioning time and alert
  on change.

---

## 13. Production considerations

* **Real HSMs differ from SoftHSM2** in ways the code already anticipates:
  far fewer sessions (size `HSM_SESSIONS` to the partition's limit divided by
  the number of service replicas), millisecond latency (raise
  `HSM_OP_TIMEOUT`, lower `HSM_ACQUIRE_TIMEOUT` so shedding happens before
  clients time out), read-only sessions for signing where RW sessions are
  limited, and `CKA_ALWAYS_AUTHENTICATE` keys that need a context-specific
  login per operation.
* **High availability**: run several replicas behind the proxy; each holds its
  own pool against an HSM HA group. The pool's recycling logic handles a
  partition failover transparently (sessions become invalid, are discarded and
  reopened).
* **Secrets**: mount the PIN from Vault/Kubernetes secrets as a file; rotate
  by restarting replicas one at a time.
* **Key lifecycle**: separate key generation (ceremony, dual control) from key
  use (this service); add key versions to ids (`arkion-intermediate-prod-v2`)
  and a deprecation window; back up wrapped copies under the KEK if the
  policy allows.
* **Capacity**: watch `hsm_pool_waiters` and `hsm_pool_acquire_timeouts_total`;
  saturation shows there before latency SLOs break. Autoscale replicas, not
  sessions, once the partition's session limit is reached.
* **Compliance**: with a FIPS-validated HSM the service already satisfies
  "keys generated and used inside the module"; SHA-256 pre-hashing is the
  standard pattern for CA signing.
* **Auditing**: forward the JSON logs (request id, key id, algorithm,
  outcome) to an immutable sink; the HSM's own audit log is the second source
  of truth.
