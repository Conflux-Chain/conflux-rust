#!/bin/bash
set -euo pipefail
ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )"/.. && pwd )"

cd $ROOT_DIR
echo "If you are running this script for the first time, please clean previous 
debug build first by running \`rm -rf target/debug\`.
This script requires cargo nightly, and is only tested on 1.43.0-nightly."

# Install dependencies
cargo install grcov

# Build binary and run unit tests with code coverage.
export CARGO_INCREMENTAL=0
# FIXME Add -Clink-dead-code after fixing the HeapSizeOf issue of SharedCache
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Coverflow-checks=off -Zno-landing-pads"
cargo +nightly build
cargo +nightly test --all

# Run python integration tests.
export CONFLUX="`pwd`/target/debug/conflux"
export CONFLUX_BENCH="`pwd`/target/debug/consensus_bench"
./tests/test_all.py

# Generate code coverage data
mkdir ccov
zip -0 ccov/ccov.zip `find . \( -name "*.gc*" \) -print`
grcov ccov/ccov.zip -s . -t html --llvm --branch --ignore-not-existing --ignore "/*" -o ccov
echo "Code coverage result is saved to directory 'ccov'. 
You can open 'ccov/index.html' with a web brower to start.

