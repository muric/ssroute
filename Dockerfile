FROM rust:1.88-bookworm

WORKDIR /app

# Install clippy
RUN rustup component add clippy

# Install dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    libsystemd-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire project
COPY . .

# Check compilation
RUN cargo check --release

# Run clippy
RUN cargo clippy --all-targets

# Build the release binary
RUN cargo build --release
