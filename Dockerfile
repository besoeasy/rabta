# syntax=docker/dockerfile:1
FROM rust:1-slim AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# stage 2 — runtime
FROM debian:bookworm-slim AS runtime
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 1000 node \
    && mkdir -p /data && chown -R node:node /data
WORKDIR /data
VOLUME /data
EXPOSE 3232
COPY --from=builder /src/target/release/rabta /usr/local/bin/rabta
USER node
ENV DATA_DIR=/data \
    PORT=3232 \
    RUST_LOG=info
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD curl -fs http://127.0.0.1:3232/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/rabta"]
