FROM rust:1.82-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p secguard-server --features ml && \
    strip target/release/secguard-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/secguard-server /usr/local/bin/secguard-server

RUN mkdir -p /var/lib/secguard/models && \
    curl -fL -# -o /var/lib/secguard/models/secguard-guard.gguf \
    https://huggingface.co/random1st/secguard-models/resolve/main/secguard-guard.gguf && \
    useradd -r -s /usr/sbin/nologin -d /var/lib/secguard secguard && \
    ln -s /var/lib/secguard/models /var/lib/secguard/.secguard && \
    chown -R secguard:secguard /var/lib/secguard

EXPOSE 8080
ENV RUST_LOG=info
ENV HOME=/var/lib/secguard
USER secguard
ENTRYPOINT ["secguard-server"]
CMD ["--port", "8080"]
