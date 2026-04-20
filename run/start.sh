ulimit -n 65535
export RUST_BACKTRACE=1
./conflux --config testnet.toml 2> stderr.txt
