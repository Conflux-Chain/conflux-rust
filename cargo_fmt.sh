#!/bin/bash
set -e

BASE_PATH=$(dirname "$(realpath "$0")")

if [[ "$1" == "--install" ]]
then
    rustup toolchain add nightly-2025-02-01
    rustup component add rustfmt --toolchain nightly-2025-02-01
    rustup component add clippy
    shift
else
    "$BASE_PATH/dev-support/cargo_all.sh" +nightly-2025-02-01 fmt --all $@
fi