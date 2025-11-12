# Conflux-Rust

Conflux-rust is a Rust-based implementation of the Conflux protocol. It is fast and
reliable.

## For Users

Please follow the [Conflux Documentation](https://doc.confluxnetwork.org/docs/category/run-a-node) to [install](https://doc.confluxnetwork.org/docs/general/run-a-node/advanced-topics/downloading-conflux-client) and [run](https://doc.confluxnetwork.org/docs/general/run-a-node/) Conflux.

## For Developers

For a general overview of the crates, see [Project Layout](./docs/repo/layout.md).

### Contribution

Thank you for considering helping out with our source code. We appreciate any
contributions, even the smallest fixes. Please read the
[guidelines](https://github.com/Conflux-Chain/conflux-rust/blob/master/CONTRIBUTING.md)
on how to submit issues and pull requests. Note that if you want to propose
significant changes to the Conflux protocol, please submit a
[CIP](https://github.com/Conflux-Chain/CIPs).

### Building

The Minimum Supported Rust Version (MSRV) of this project is `1.90`

See the doc for detailed instructions on how to [build from source](./docs/build-from-source.md).

If you have modified any Rust code, please run the cargo_fmt.sh script before committing to format the code and ensure consistent code style.

### Unit Tests

Unit tests come together with the Rust code. They can be invoked via `cargo test --release --all`. See the
[Getting Started](https://doc.confluxnetwork.org/docs/general/run-a-node/)
page for more information.

### Integration Tests

Integration tests are Python test scripts with the `_test.py` suffix in the `tests` directory and in the `integration_tests/tests` directory.
To run these tests:

1. Setting up and activating a NEW virtual env via `source ./dev-support/activate_new_venv.sh`. This command will create a new one with Python `3.11` to `.venv` and activate it each time you run it. Or you can simply run `.venv/bin/activate` to activate the created one.
2. Install the required Python packages using `bash ./dev-support/dep_pip3.sh` in the root directory.
3. Compile Conflux in _release_ mode using `cargo build --release`
4. Compile the `consensus_bench binary` using `cd tools/consensus_bench && cargo build --release`
5. Fetch all submodule using `git submodule update --remote --recursive --init`.

Then, you can run all integration tests using:

- `python3 tests/test_all.py` for tests in the `tests` directory
- `pytest ./integration_tests/tests -vv -n 6 --dist loadscope` for tests in the `integration_tests` directory

> As for running tests with coverage, please refer to [Coverage](./docs/coverage.md).

## Resources

- [Conflux Website](https://www.confluxnetwork.org/)
- [Conflux Scan](https://www.confluxscan.org/)
- [Conflux Paper](https://arxiv.org/abs/1805.03870)
- [Medium](https://medium.com/@ConfluxNetwork)

## License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)
