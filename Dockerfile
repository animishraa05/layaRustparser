# ULPF — air-gapped syslog pre-processing + Merkle integrity fabric.
#
# Portable multi-arch image (linux/amd64, linux/arm64). Build with:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ulpf:0.1.0 .
# Or for the local machine only:
#   docker compose up --build -d
#
# The release binaries stay < 35 MB; the image adds a minimal Debian
# runtime around them (do not confuse the two numbers).

ARG RUST_VERSION=1.96

# ---------- Stage 1: build ----------
FROM rust:${RUST_VERSION}-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Dependency layer first for better caching.
COPY rust-toolchain.toml Cargo.toml Cargo.lock* ./
COPY crates ./crates

RUN cargo build --release -p ulpf-cli -p ulpf-generator \
    && strip target/release/ulpf target/release/ulpf-generator || true

# ---------- Stage 2: runtime ----------
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="ULPF" \
      org.opencontainers.image.description="Universal Log Pre-processing Framework: OCSF 1.3 normalization + RFC 6962 Merkle integrity" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /opt/ulpf

# ca-certificates: TLS-ready base. python3: runs scripts/simulate_tamper.py
# inside the container. procps: powers the HEALTHCHECK below.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates python3 procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /usr/sbin/nologin ulpf
# NOTE: UID 1000 matches the typical host user, so bind-mounted ./data
# stays writable. On Linux with a different UID, run:
#   chown -R $(id -u):$(id -g) data/

COPY --from=builder /app/target/release/ulpf /app/target/release/ulpf-generator /usr/local/bin/
COPY data ./data
COPY scripts ./scripts
COPY docs ./docs

RUN mkdir -p /opt/ulpf/data/parquet /opt/ulpf/data/parsers \
    && chown -R ulpf:ulpf /opt/ulpf

USER ulpf

# Syslog ingestion ports (unprivileged, safe for non-root).
EXPOSE 5140/udp 5140/tcp

ENV RUST_LOG=info

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pidof ulpf || exit 1

ENTRYPOINT ["ulpf"]
CMD ["ingest", "--udp", "0.0.0.0:5140", "--tcp", "0.0.0.0:5140", \
     "--parquet-dir", "/opt/ulpf/data/parquet", "--ledger", "/opt/ulpf/data/ledger.jsonl", \
     "--batch-size", "1000", "--batch-timeout", "2000"]
