FROM rust:1.92-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      nasm \
      perl \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build -p toppy-gw --release

FROM rust:1.92-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/toppy-gw /usr/local/bin/toppy-gw

EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --retries=5 CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["toppy-gw"]
