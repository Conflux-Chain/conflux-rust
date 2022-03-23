ulimit -n 10000
export RUST_BACKTRACE=1
./conflux --config testnet.toml 2> stderr.txt
