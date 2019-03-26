# Conflux-Rust
[![Travis](https://travis-ci.com/Conflux-Chain/conflux-rust.svg?branch=master)](https://travis-ci.com/Conflux-Chain/conflux-rust#)

Conflux-rust is a rust-based implementation of Conflux protocol, it is fast and reliable.

# Build Instruction

1. Install rust.
2. rustup update.
3. Make sure you are using the stable branch.
4. Install clang for compiling rocksdb.
5. Install other dependencies for rocksdb. Instruction can be found in https://github.com/facebook/rocksdb/blob/master/INSTALL.md

# Test Instruction

1. Install solc to compile solidity.
2. Run dev-support/dep_pip3.sh to install extra python3 packages for running test.
3. Run the python scripts in test directory.

Note that there is another sha3 package which does not contain necessary function. Do not install that package! Install pysha3 instead.

# Contribution

Thank you for considering helping out with our source code. We appreciate any contributions, even the smallest fixes.

Here are some guidelines before you start:
* Please fork the project to contribute your pull requests.
* If you wish to submit complex changes, please fire an [issue](https://github.com/Conflux-Chain/conflux-rust/issues) to communicate with the core devs first. 
* Pull requests need to be based on and opened against the `master` branch.
* Code must be formatted using [cargo_fmt.sh](https://github.com/Conflux-Chain/conflux-rust/blob/master/cargo_fmt.sh).
* We use reviewable.io as our code review tool for any pull request.

# Resources

* [Conflux Website](https://www.conflux-chain.org/)
* [Conflux Paper](https://arxiv.org/abs/1805.03870)
* [Medium](https://medium.com/@Confluxchain)

# License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)