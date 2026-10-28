# syntax=docker/dockerfile:1.7
# ---- build stage -----------------------------------------------------------
ARG RUST_VERSION=1.99
FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /src

# Cache dependency compilation separately from the application sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
 && echo 'fn main() {}' > src/main.rs \
 && echo 'fn main() {}' > src/bin/bench.rs \
 && touch src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src target/release/.fingerprint/hsm-signer-* \
           target/release/deps/libhsm_signer* target/release/deps/hsm_signer-* \
           target/release/deps/hsm-signer-* target/release/deps/hsm-bench-* \
           target/release/hsm-signer* target/release/hsm-bench*

COPY src ./src
RUN find src -type f -exec touch {} + \
 && cargo build --release --locked \
 && strip target/release/hsm-signer target/release/hsm-bench

# ---- runtime stage ---------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 opensc ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --gid 0 --home-dir /nonexistent --shell /usr/sbin/nologin hsm \
 && mkdir -p /var/lib/softhsm/tokens /etc/hsm-signer \
 && chown -R hsm:0 /var/lib/softhsm && chmod 770 /var/lib/softhsm/tokens \
 && chmod 755 /etc/hsm-signer

# Explicit modes: the service runs as a non-root user and must not depend on
# the umask of whoever built the image.
COPY --chmod=0755 --from=builder /src/target/release/hsm-signer /usr/local/bin/hsm-signer
COPY --chmod=0755 --from=builder /src/target/release/hsm-bench  /usr/local/bin/hsm-bench
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=0644 docker/softhsm2.conf /etc/hsm-signer/softhsm2.conf
COPY --chmod=0644 keys.yaml /etc/hsm-signer/keys.yaml

ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    SOFTHSM2_CONF=/etc/hsm-signer/softhsm2.conf \
    KEYS_CONFIG=/etc/hsm-signer/keys.yaml \
    HSM_TOKEN_LABEL=arkion \
    LISTEN_ADDR=0.0.0.0:8080 \
    LOG_FORMAT=json \
    RUST_LOG=info

USER hsm
VOLUME ["/var/lib/softhsm/tokens"]
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/readyz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["hsm-signer", "serve"]
