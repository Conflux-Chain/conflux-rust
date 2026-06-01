# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0

FROM rust:1.94

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    python3 xxd file gdb protobuf-compiler \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone Conflux-rust at specific commit
RUN git clone https://github.com/Conflux-Chain/conflux-rust.git . && \
    git checkout 2dfb5f91babd5c1d1fe24e77e7dd9104e772a123 && \
    git submodule update --init --recursive

# Copy entry harness for fuzzing
COPY entry.rs /work/entry.rs

# Build the release binary and entry harness
RUN cargo build --release --features default 2>&1 | tail -20

# Verify binary exists
RUN ls -lh /work/target/release/conflux || (echo "Build failed" && exit 1)

CMD ["/bin/bash"]
