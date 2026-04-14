FROM rust:1.88-bookworm

WORKDIR /app

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

# Build the release binary
RUN cargo build --release
