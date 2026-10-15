# Build from the repository root: docker build -f deploy/Dockerfile .
FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p armada-matrix

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/armada-matrix /usr/local/bin/armada-matrix
WORKDIR /data
# Mount config.toml, registration.yaml and the crypto/ directory here.
VOLUME /data
CMD ["armada-matrix", "-c", "/data/config.toml"]
