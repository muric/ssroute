FROM rust:1.88-bookworm

RUN rustup component add clippy

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cargo clippy --all-targets --all-features -- -D warnings

RUN cargo build --release

CMD ["cargo", "help"]
