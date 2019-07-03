rustup toolchain add nightly-2019-02-13
rustup component add rustfmt --toolchain nightly-2019-02-13-x86_64-apple-darwin
cargo +nightly-2019-02-13 fmt --all
