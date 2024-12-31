FROM docker.io/rust:alpine AS base

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
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

FROM docker.io/alpine
WORKDIR /app
COPY --from=builder /app/target/release/toy_backend toy_backend
COPY migrations migrations
ENV RUST_LOG=info
ENTRYPOINT ["./toy_backend"]
