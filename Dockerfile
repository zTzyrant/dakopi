# --- Stage 1: Builder ---
FROM rust:latest as builder

WORKDIR /app

# 1. Install build dependencies
RUN apt-get update && apt-get install -y cmake pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# 2. Copy file manifest utama & migration
COPY Cargo.toml Cargo.lock ./
COPY migration/Cargo.toml ./migration/Cargo.toml

# 3. Dummy build untuk cache dependencies
RUN mkdir -p src migration/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > migration/src/main.rs \
    && touch migration/src/lib.rs

RUN cargo build --release

# 4. Hapus dummy dan copy source code asli
RUN rm -rf src migration/src
COPY src ./src
COPY migration/src ./migration/src

# 5. Build Aplikasi Final & Migration Binary
RUN touch src/main.rs migration/src/main.rs
RUN cargo build --release

# --- Stage 2: Runner ---
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary
COPY --from=builder /app/target/release/dakopi /app/dakopi
COPY --from=builder /app/target/release/migration /app/migration

# Copy konfigurasi Casbin
RUN mkdir -p src/auth
COPY src/auth/rbac_model.conf /app/src/auth/rbac_model.conf

EXPOSE 3000

# Jalankan migrasi lalu jalankan aplikasi
CMD ./migration && ./dakopi