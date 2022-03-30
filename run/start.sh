ulimit -n 10000
export RUST_BACKTRACE=1
./conflux --config hydra.toml 2> stderr.txt
