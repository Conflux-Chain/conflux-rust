# Conflux-Rust

Conflux-rust is a rust-based implementation of Conflux protocol, it is fast and
reliable. Please follow the [Conflux
Documentation](https://developer.conflux-chain.org/) to
[build](https://developer.conflux-chain.org/docs/conflux-doc/docs/installation)
and
[run](https://developer.conflux-chain.org/docs/conflux-doc/docs/get_started)
Conflux.

This version depends on rustc 1.47.0.

## Contribution

Thank you for considering helping out with our source code. We appreciate any
contributions, even the smallest fixes. Please read the
[guideline](https://github.com/Conflux-Chain/conflux-rust/blob/master/CONTRIBUTING.md)
on how to submit issues and pull requests. Note that if you want to propose
significant changes to the Conflux protocol. Please submit a
[CIP](https://github.com/Conflux-Chain/CIPs). 

## Unit Tests and Integration Tests

Unit tests come together with the rust code. It can be invoked via `cargo test
--release --all` after Conflux being compiled from the source code. See the
[Getting Started](https://conflux-chain.github.io/conflux-doc/get_started/)
page for more information. Integration tests are python test scripts ended with
`_test.py` in the `tests` directory. To run these tests, first compile Conflux
in *release* mode using `cargo build --release`. Then, you can run all
integration tests using the script `tests/test_all.py`.

## Resources

* [Conflux Website](https://www.conflux-chain.org/)
* [Conflux Scan](https://www.confluxscan.io/)
* [Conflux Paper](https://arxiv.org/abs/1805.03870)
* [Medium](https://medium.com/@ConfluxNetwork)

## License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)
