#!/bin/bash
set -e
if [[ "$1" == "--install" ]]
then
    rustup toolchain add nightly-2024-02-04
    rustup component add rustfmt --toolchain nightly-2024-02-04
    rustup component add clippy
    shift
fi
cargo +nightly-2024-02-04 fmt --all $@
