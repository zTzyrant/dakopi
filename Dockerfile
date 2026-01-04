# --- Stage 1: Builder ---
FROM rust:latest as builder

WORKDIR /app

# Copy manifest
COPY Cargo.toml Cargo.lock ./

# Dummy build untuk cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Hapus dummy dan copy source code asli
RUN rm -rf src
COPY src ./src

# Build aplikasi
RUN touch src/main.rs
RUN cargo build --release

# --- Stage 2: Runner ---
FROM debian:bookworm-slim

# Install OpenSSL
RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy hasil build (HANYA binary, tanpa templates)
COPY --from=builder /app/target/release/dakopi /app/dakopi

EXPOSE 3000

CMD ["./dakopi"]