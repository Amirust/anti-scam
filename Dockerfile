# trixie, not bookworm: the prebuilt static ONNX Runtime needs glibc >= 2.38
# and a GCC 13+ libstdc++ at link and run time
FROM rust:1.90-trixie AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

# target/ and the cargo registry live in cache mounts, so the binary must be
# copied out of the cache before the layer is finalized
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && cp target/release/anti-scam /build/anti-scam

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/anti-scam /usr/local/bin/anti-scam

# the sqlite database (data.db) is created in the working directory
WORKDIR /data

ENV BANNED_CONFIG=/config/banned.json \
    CONFIG_PATH=/config/config.toml

CMD ["anti-scam"]
