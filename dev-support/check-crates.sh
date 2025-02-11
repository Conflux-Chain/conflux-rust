#!/bin/bash

set -e
grep -oP '^\s*\K[\w-]+(?=\s*=\s*{ path)' Cargo.toml | \
xargs -I {} sh -c \
    'echo "\n\033[1;36m    Checking individual crate {}\033[0m\n" && \
    cargo check -p {} && \
    cargo check --tests -p {}' 
cargo check -p cfx-addr --no-default-features --tests
