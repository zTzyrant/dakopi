# --- Stage 1: Builder ---
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY migration/Cargo.toml ./migration/Cargo.toml

# Dummy build for caching dependencies
RUN mkdir -p src migration/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > migration/src/main.rs \
    && touch migration/src/lib.rs

RUN cargo build --release --workspace

# Copy real source code
RUN rm -rf src migration/src
COPY src ./src
COPY migration/src ./migration/src

# Final build
RUN touch src/main.rs migration/src/main.rs
RUN cargo build --release --workspace

# --- Stage 2: Runner ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries
COPY --from=builder /app/target/release/dakopi ./dakopi
COPY --from=builder /app/target/release/migration ./migration

# Copy config
RUN mkdir -p src/auth
COPY src/auth/rbac_model.conf ./src/auth/rbac_model.conf

EXPOSE 3000

# Default command (akan ditimpa oleh railway.toml jika ada)
CMD ["./dakopi"]