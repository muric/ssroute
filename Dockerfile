FROM rust:1.88-bookworm AS builder

WORKDIR /app

# Install clippy
RUN rustup component add clippy

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

CMD ["cargo", "help"]
