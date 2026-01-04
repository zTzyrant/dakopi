# --- Stage 1: Builder (Untuk Compile Rust) ---
FROM rust:latest as builder

# Buat folder kerja
WORKDIR /app

# Copy file manifest dulu (agar dependencies di-cache)
COPY Cargo.toml Cargo.lock ./

# Buat dummy main.rs untuk build dependencies saja (trik agar build cepat)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Hapus dummy main dan copy source code asli
RUN rm -rf src
COPY src ./src
COPY templates ./templates 
# ^ JANGAN LUPA: Jika kamu punya folder 'templates' atau 'assets', copy juga di sini!

# Build aplikasi sesungguhnya
# Kita 'touch' main.rs agar cargo tahu ada perubahan
RUN touch src/main.rs
RUN cargo build --release

# --- Stage 2: Runner (Image Akhir yang Ringan) ---
# Gunakan debian-slim agar kecil tapi tetap kompatibel dengan library standar (OpenSSL)
FROM debian:bookworm-slim

# Install OpenSSL & CA Certificates (PENTING untuk koneksi ke Aiven/Brevo/Google!)
RUN apt-get update && apt-get install -y \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy hasil build dari Stage 1
COPY --from=builder /app/target/release/dakopi /app/dakopi
# Copy folder templates/assets jika ada
COPY --from=builder /app/templates /app/templates

# Expose port (Railway akan override ini, tapi formalitas)
EXPOSE 3000

# Jalankan aplikasi
CMD ["./dakopi"]