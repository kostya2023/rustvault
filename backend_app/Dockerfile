
# ---------- chef: base image with cargo-chef ----------
FROM rust:1.98-alpine AS chef

RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    openssl-libs-static \
    perl \
    make \
    curl

ENV OPENSSL_STATIC=1

RUN rustup target add x86_64-unknown-linux-musl
RUN cargo install cargo-chef --locked

WORKDIR /app

# ---------- planner: generate recipe.json ----------
FROM chef AS planner

COPY . .

RUN cargo chef prepare --recipe-path recipe.json

# ---------- builder: dependencies first, then source ----------
FROM chef AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook \
    --release \
    --locked \
    --target x86_64-unknown-linux-musl \
    --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations

RUN cargo build \
    --locked \
    --release \
    --target x86_64-unknown-linux-musl \
    --bin backend_app

# ---------- runtime: minimal Alpine ----------
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 1001 -s /sbin/nologin app

WORKDIR /app

COPY --from=builder \
    /app/target/x86_64-unknown-linux-musl/release/backend_app \
    /usr/local/bin/backend_app

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/backend_app"]
