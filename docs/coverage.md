# Tests With Coverage

We use `cargo-llvm-cov` to generate coverage reports for tests.

## Install Dependencies

```bash
cargo +stable install cargo-llvm-cov --locked
```

## Setup Environment Variables

```bash
# Set the environment variables needed to get coverage.
# This command sets the RUSTFLAGS and other environment variables
source <(cargo llvm-cov show-env --export-prefix)
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

```bash
# Run integration tests
pytest integration_tests/tests -vv -n 6 --dist loadscope --conflux-binary $(pwd)/target/debug/conflux

# Set up benchmark binary path before running `python tests/test_all.py`
export CONFLUX_BENCH=$(pwd)/target/debug/consensus_bench
# Run additional tests
python tests/test_all.py --conflux-binary $(pwd)/target/debug/conflux
```

`*.profraw` files will be generated in `./target/`

## Generate Coverage Report

```bash
cargo llvm-cov report --html --failure-mode=all # Generated report will be in `./target/llvm-cov/html/index.html`
```
