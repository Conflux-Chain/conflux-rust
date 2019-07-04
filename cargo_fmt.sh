#!/bin/bash
if [[ "$1" == "--install" ]]
then
    rustup toolchain add nightly-2019-07-03
    rustup component add rustfmt --toolchain nightly-2019-07-03
    shift
fi
cargo +nightly-2019-07-03 fmt --all $@
