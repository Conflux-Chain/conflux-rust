# Conflux-Rust

Conflux-rust is a rust-based implementation of Conflux protocol, it is fast and reliable. Please follow the [Conflux Documentation](https://conflux-chain.github.io/conflux-doc/) to [build](https://conflux-chain.github.io/conflux-doc/install/) and [run](https://conflux-chain.github.io/conflux-doc/get_started/) Conflux.

This version depends on rustc 1.42.0.

## Contribution

Thank you for considering helping out with our source code. We appreciate any contributions, even the smallest fixes. Please read the [guideline](https://github.com/Conflux-Chain/conflux-rust/blob/master/CONTRIBUTING.md) on how to submit issues and pull requests. Note that if you want to propose significant changes to the Conflux protocol. Please submit a [CIP](https://github.com/Conflux-Chain/CIPs). 

## Unit Tests and Integration Tests

Unit tests come together with the rust code. It can be invoked via `cargo test
--release --all` after Conflux being complied from the source code. See the
[Getting Started](https://conflux-chain.github.io/conflux-doc/get_started/)
page for more information. Integration tests are python test scripts ended with
`_test.py` in the `tests/scripts` directory. After compiled the *release*
version of the Conflux from code. One can run `tests/test_all.py` to run all
integration tests together. 

## Resources

* [Conflux Website](https://www.conflux-chain.org/)
* [Conflux Scan](https://www.confluxscan.io/)
* [Conflux Paper](https://arxiv.org/abs/1805.03870)
* [Medium](https://medium.com/@ConfluxNetwork)

## License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)
