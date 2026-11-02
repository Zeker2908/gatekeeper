# syntax=docker/dockerfile:1

ARG RUST_VERSION=1.99.1
ARG BIN_NAME=gatekeeper

# ---------- сборка ----------
FROM rust:${RUST_VERSION}-bookworm AS builder
ARG BIN_NAME
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked \
    && cp target/release/${BIN_NAME} /app/gatekeeper

# ---------- рантайм ----------
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /app/gatekeeper /usr/local/bin/gatekeeper

ENV BIND_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/gatekeeper"]