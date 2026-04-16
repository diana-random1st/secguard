FROM rust:1.82-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p secguard-server && \
    strip target/release/secguard-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/secguard-server /usr/local/bin/secguard-server

EXPOSE 8080
ENV RUST_LOG=info
USER nobody
ENTRYPOINT ["secguard-server"]
CMD ["--port", "8080"]
