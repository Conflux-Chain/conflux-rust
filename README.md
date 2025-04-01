# Conflux-Rust

Conflux-rust is a Rust-based implementation of the Conflux protocol. It is fast and
reliable. 

## For Users

Please follow the [Conflux
Documentation](https://doc.confluxnetwork.org/) to
[build](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/compiling-conflux-client)
and
[run](https://doc.confluxnetwork.org/docs/general/run-a-node/)
Conflux.

## For Developers

For a general overview of the crates, see [Project Layout](./docs/repo/layout.md).

### Contribution

Thank you for considering helping out with our source code. We appreciate any
contributions, even the smallest fixes. Please read the
[guidelines](https://github.com/Conflux-Chain/conflux-rust/blob/master/CONTRIBUTING.md)
on how to submit issues and pull requests. Note that if you want to propose
significant changes to the Conflux protocol, please submit a
[CIP](https://github.com/Conflux-Chain/CIPs).

### Unit Tests and Integration Tests

Unit tests come together with the Rust code. They can be invoked via `cargo test --release --all`. See the
[Getting Started](https://doc.confluxnetwork.org/docs/general/run-a-node/)
page for more information. 

Integration tests are Python test scripts with the `_test.py` suffix in the `tests` directory and in the `integration_tests/tests` directory.
To run these tests, first compile Conflux in _release_ mode using `cargo build --release` and 
fetch all submodule using `git submodule update --remote --recursive --init`.
Then, you can run all integration tests using:

- `tests/test_all.py` for tests in the `tests` directory
- `pytest ./integration_tests/tests -vv -n 6 --dist loadscope` for tests in the `integration_tests` directory

### Integration Tests With Coverage

#### Install Dependencies

```bash
rustup component add llvm-tools-preview
cargo install grcov
```

#### Build Instrumented Binary

Ensure previous builds are clean:

```bash
cargo clean
```

Build with coverage:

```bash
mkdir -p target/cov/profraw
export LLVM_PROFILE_FILE=$(pwd)/target/cov/profraw/%p-%m.profraw

export RUSTFLAGS="-C instrument-coverage"
cargo build
```

The built binary will be in `target/debug` (`target/debug/conflux`).

#### Run Integration Tests

It is recommended to specify a folder for the profraw files:

```bash
mkdir -p target/cov/profraw
export LLVM_PROFILE_FILE=$(pwd)/target/cov/profraw/%p-%m.profraw
```

It is also ok to specify the path yourself, but under current directory.

Run integration tests specifying binary path:

```bash
pytest integration_tests/tests -vv -n 6 --dist loadscope --conflux-binary $(pwd)/target/debug/conflux
export CONFLUX_BENCH=$(pwd)/target/debug/consensus_bench
python tests/test_all.py --conflux-binary $(pwd)/target/debug/conflux
```

You would find the profile data in `target/cov/profraw`.

#### Generate Coverage Report

```bash
grcov . --binary-path ./target/debug/ -s . --ignore-not-existing --ignore '/rustc/*' --ignore 'target/*' -t html -o target/cov/html 
```

The coverage report will be in `target/cov/index.html`.


## Resources

- [Conflux Website](https://www.confluxnetwork.org/)
- [Conflux Scan](https://www.confluxscan.org/)
- [Conflux Paper](https://arxiv.org/abs/1805.03870)
- [Medium](https://medium.com/@ConfluxNetwork)

## License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)
