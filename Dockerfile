# ==============================================================================
# Stage 1 : Compilation du binaire Rust (Builder)
# ==============================================================================
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/mod_aim
COPY Cargo.toml ./
COPY src ./src
COPY tools ./tools

RUN cargo build --release

# ==============================================================================
# Stage 2 : Image d'exécution minimale Zero-Trust (Debian Bookworm Slim)
# ==============================================================================
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin aim-runner \
    && mkdir -p /app/tools /data \
    && chown -R aim-runner:aim-runner /app /data

WORKDIR /app

COPY --from=builder /usr/src/mod_aim/target/release/aim-daemon /usr/local/bin/aim-daemon
COPY --chown=aim-runner:aim-runner tools/*.aim /app/tools/

USER aim-runner

# Port 8080 : Data Plane Public (MCP / REST / llms.txt)
# Port 8081 : Control Plane Humain Isolé (/_admin protégé par AIM_ADMIN_PASSWORD)
ENV AIM_BIND_ADDR="0.0.0.0:8080"
ENV AIM_ADMIN_BIND_ADDR="0.0.0.0:8081"
ENV AIM_TOOLS_DIR="/app/tools"
ENV AIM_DB_PATH="/data/engine.sqlite"
ENV RUST_LOG="info"

VOLUME ["/app/tools", "/data"]
EXPOSE 8080 8081

CMD ["/usr/local/bin/aim-daemon"]
