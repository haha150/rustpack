FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        mingw-w64 \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Inject corporate CA certs for TLS-intercepting proxies
COPY deploy/ca-certificates/ /tmp/certs/
RUN find /tmp/certs -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" \) | head -1 | \
    grep -q . && { \
      cp /tmp/certs/*.crt /usr/local/share/ca-certificates/ 2>/dev/null; \
      for f in /tmp/certs/*.cer; do [ -f "$f" ] && cp "$f" "/usr/local/share/ca-certificates/$(basename "${f%.cer}.crt")"; done; \
      for f in /tmp/certs/*.pem; do [ -f "$f" ] && cp "$f" "/usr/local/share/ca-certificates/$(basename "${f%.pem}.crt")"; done; \
      update-ca-certificates; \
    } || true

# Install Rust via rustup
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal && \
    . /opt/cargo/env && \
    rustup target add x86_64-pc-windows-gnu
ENV PATH="/opt/cargo/bin:${PATH}"

# Configure cross-compilation linker
RUN printf '[target.x86_64-pc-windows-gnu]\nlinker = "x86_64-w64-mingw32-gcc"\n' \
    > /opt/cargo/config.toml

WORKDIR /rustpack

# Copy manifests and fetch dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub fn dummy() {}" > src/lib.rs && \
    cargo fetch && \
    rm -rf src

# Copy full source and build
COPY src src
COPY tests tests
RUN cargo build --release

ENTRYPOINT ["./target/release/rustpack"]
