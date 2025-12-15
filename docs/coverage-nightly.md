# Tests With Coverage

> NOTE: This document is for coverage with nightly rust toolchain which supports branch coverage.
> If you are using stable rust toolchain, please refer to [coverage.md](coverage.md).

## Install Dependencies

```bash
rustup toolchain install nightly-2025-02-01
rustup override set nightly-2025-02-01
cargo +stable install cargo-llvm-cov --locked
```

## Setup Environment Variables

```bash
# Set the environment variables needed to get coverage.
# This command sets the RUSTFLAGS and other environment variables
source <(cargo llvm-cov show-env --branch --export-prefix)
```

It should note that in certain cases, you might want to add additional flags to the `RUSTFLAGS` environment variable. For example, on certain version of OSX, you might need to add the following flag:

```bash
echo $RUSTFLAGS
# You will see something like this: `-C instrument-coverage --cfg=coverage --cfg=trybuild_no_target`
export RUSTFLAGS="${RUSTFLAGS} -L /opt/homebrew/opt/bzip2/lib -l bz2"
```

## Build Instrumented Binary

```bash
# Remove artifacts that may affect the coverage results.
# This command should be called after show-env.
cargo llvm-cov clean --workspace
# Above two commands should be called before build binaries.

cargo build # Build rust binaries, binaries would be in target/debug/*
```

## Run Tests

Run unit tests:

```bash
cargo nextest run --no-fail-fast --workspace
cargo nextest run --no-fail-fast -p cfx-addr --no-default-features
```

Run integration tests:

> It should be noted that we compile the binary in debug mode, so the performance is not good.
> You might need to change parallel parameters if frequent io error or timeout error occurs.

```bash
# Run integration tests
# Change -n to control the number of tests running in parallel.
pytest integration_tests/tests -vv -n 6 --dist loadscope --conflux-binary $(pwd)/target/debug/conflux

# Set up benchmark binary path before running `python tests/test_all.py`
export CONFLUX_BENCH=$(pwd)/tools/consensus_bench/target/debug/consensus_bench
# Run additional tests.
# Use --max-workers and --max-nodes to control the number of workers and nodes.
python tests/test_all.py --max-workers 6 --conflux-binary $(pwd)/target/debug/conflux
```

`*.profraw` files will be generated in `./target/`

## Generate Coverage Report

```bash
cargo llvm-cov report --branch --html --failure-mode=all # Generated report will be in `./target/llvm-cov/html/index.html`
```
