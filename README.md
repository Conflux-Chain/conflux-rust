# Conflux-Rust

|**`Travis`**|
|---------------|
|[![Travis](https://travis-ci.com/Conflux-Chain/conflux-rust.svg?branch=master)](https://travis-ci.com/Conflux-Chain/conflux-rust#)|

Conflux-rust is a rust-based implementation of Conflux protocol, it is fast and reliable.

## Build Instruction

1. Install Rust. Instructions can be found [here](https://www.rust-lang.org/).
2. To make sure that you are using the most updated and stable branch:
```
rustup update
```
3. Install clang for compiling rocksdb.
4. Install other dependencies for rocksdb. Instructions can be found [here](https://github.com/facebook/rocksdb/blob/master/INSTALL.md).
5. To build the project:
```
cargo build
```

## Run Instruction

1. Edit the configuration file `run/default.toml`: 
    * Set `public_address` according to your public IP.
    * If `start_mining=true`:
      - Set `mining_author` to the account address to receive mining reward.
3. To run `conflux` with the configuration specified:
```
./target/release/conflux --config default.toml
```

## Test Instruction

1. Install solc to compile solidity. Instructions can be found [here](https://solidity.readthedocs.io).
2. Install extra python3 packages by running `dev-support/dep_pip3.sh` 
3. Run the python scripts under `test` directory.

**Note that there is another sha3 package which does not contain necessary function. Do not install that package! Install pysha3 instead.

## Contribution Instruction

Thank you for considering helping out with our source code. We appreciate any contributions, even the smallest fixes.

Here are some guidelines before you start:
* Please fork the project to contribute your pull requests.
* If you wish to submit complex changes, please create an [GitHub issues](https://github.com/Conflux-Chain/conflux-rust/issues) to communicate with the core devs first. 
* Pull requests need to be based on and opened against the `master` branch.
* Code must be formatted using [cargo_fmt.sh](https://github.com/Conflux-Chain/conflux-rust/blob/master/cargo_fmt.sh).
* We use [reviewable.io](https://reviewable.io/) as our code review tool for any pull request.

## Resources

* [Conflux Website](https://www.conflux-chain.org/)
* [Conflux Paper](https://arxiv.org/abs/1805.03870)
* [Medium](https://medium.com/@Confluxchain)

## License

[GNU General Public License v3.0](https://github.com/Conflux-Chain/conflux-rust/blob/master/LICENSE)
