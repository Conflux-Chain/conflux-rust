#!/bin/bash

rustup toolchain add nightly-2019-07-03
rustup component add rustfmt --toolchain nightly-2019-07-03
cargo +nightly-2019-07-03 fmt --all $@
