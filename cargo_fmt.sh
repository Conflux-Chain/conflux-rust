#!/bin/bash
set -e

BASE_PATH=$(dirname "$(realpath "$0")")

if [[ "$1" == "--install" ]]
then
    rustup toolchain add nightly-2024-02-04
    rustup component add rustfmt --toolchain nightly-2024-02-04
    rustup component add clippy
    shift
else
    "$BASE_PATH/dev-support/cargo_all.sh" +nightly-2024-02-04 fmt --all $@
fi