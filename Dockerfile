# Multi-stage build using cargo-chef for dependency caching
FROM lukemathwalker/cargo-chef:latest-rust-alpine AS chef
WORKDIR /usr/src/midtrans-webhooker

# Install build dependencies for OpenSSL static build on musl
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig
ENV OPENSSL_STATIC=1

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /usr/src/midtrans-webhooker/recipe.json recipe.json
# Build dependencies - this layer is cached unless Cargo.toml or Cargo.lock changes
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source code and build the application binary
COPY . .
RUN cargo build --release --bin midtrans-webhooker

# Final minimal runtime image
FROM alpine:latest AS runtime

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy compiled binary from builder
COPY --from=builder /usr/src/midtrans-webhooker/target/release/midtrans-webhooker /app/midtrans-webhooker

# Expose default port
EXPOSE 3000

ENV PORT=3000

CMD ["/app/midtrans-webhooker"]
