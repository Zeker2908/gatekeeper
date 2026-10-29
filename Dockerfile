# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.99.1
ARG BIN_NAME=gatekeeper

# ---------- сборка ----------
FROM rust:${RUST_VERSION}-bookworm AS builder
ARG BIN_NAME
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev cmake \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp target/release/${BIN_NAME} /app/gatekeeper

# ---------- рантайм ----------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin gatekeeper

COPY --from=builder /app/gatekeeper /usr/local/bin/gatekeeper

USER 10001
ENV BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health/live || exit 1

ENTRYPOINT ["gatekeeper"]
