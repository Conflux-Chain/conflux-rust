ulimit -n 65535
export RUST_BACKTRACE=1
./conflux --config pos_testnet.toml 2> stderr.txt
