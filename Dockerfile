FROM rust:1.94-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends clang libclang-dev cmake && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p secguard-server && \
    strip target/release/secguard-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -r -s /usr/sbin/nologin -d /var/lib/secguard secguard && \
    mkdir -p /var/lib/secguard/.secguard/models && \
    chown -R secguard:secguard /var/lib/secguard
COPY --from=builder /src/target/release/secguard-server /usr/local/bin/secguard-server

EXPOSE 8080
ENV RUST_LOG=info
ENV HOME=/var/lib/secguard
USER secguard
ENTRYPOINT ["secguard-server"]
CMD ["--port", "8080"]
