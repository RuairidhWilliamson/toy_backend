FROM docker.io/rust:1.85-alpine AS base

RUN apk add gcc g++ git pkgconfig curl
RUN cargo install cargo-chef --locked
WORKDIR /app

FROM base AS planner
COPY . .
# Quickly generate recipe.json
RUN cargo chef prepare --recipe-path recipe.json

FROM base AS builder
COPY --from=planner /app/recipe.json recipe.json
# Caches if recipe.json is the same
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM docker.io/alpine
WORKDIR /app
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/toy_backend toy_backend
COPY migrations migrations
COPY templates templates

ENV RUST_LOG=info
ENV MIGRATIONS_DIR=migrations
ENV TEMPLATES_DIR=templates

ENTRYPOINT ["./toy_backend"]
