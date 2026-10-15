# Multi-stage build for Rust (minimal static Alpine image)
FROM rust:alpine AS builder

# Install build dependencies for OpenSSL static build on musl
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Force static linking of OpenSSL
ENV OPENSSL_STATIC=1

WORKDIR /usr/src/midtrans-webhooker

# Copy manifests first to leverage Docker layer caching
COPY Cargo.toml Cargo.lock* ./

# Copy actual source code
COPY src ./src
COPY tests ./tests

# Build release binary
RUN cargo build --release

# Final runtime image
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy compiled binary from builder
COPY --from=builder /usr/src/midtrans-webhooker/target/release/midtrans-webhooker /app/midtrans-webhooker

# Expose default port
EXPOSE 3000

ENV PORT=3000

CMD ["/app/midtrans-webhooker"]
