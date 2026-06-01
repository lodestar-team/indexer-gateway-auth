# syntax=docker/dockerfile:1

# ---- builder ----------------------------------------------------------------
FROM rust:1.88-slim-bookworm AS builder
WORKDIR /build

# Pre-build dependencies against stub sources for better layer caching: this
# layer only changes when Cargo.toml/Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && : > src/lib.rs \
    && cargo build --release --locked || true

# Real sources.
COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --bin indexer-gateway-auth \
    && strip target/release/indexer-gateway-auth

# ---- runtime ----------------------------------------------------------------
# distroless/cc provides glibc + libgcc for the ring/aws-lc crypto backends.
FROM gcr.io/distroless/cc-debian12:nonroot
LABEL org.opencontainers.image.title="indexer-gateway-auth" \
      org.opencontainers.image.description="Authenticating reverse proxy for the Graph Indexer Management API" \
      org.opencontainers.image.source="https://github.com/lodestar-team/indexer-gateway-auth" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/release/indexer-gateway-auth /usr/local/bin/indexer-gateway-auth

# Proxy listener and Prometheus metrics.
EXPOSE 8400 7300

# Runs as the distroless `nonroot` user (uid 65532) by default.
ENTRYPOINT ["/usr/local/bin/indexer-gateway-auth"]
CMD ["--config", "/etc/iga/config.toml"]
