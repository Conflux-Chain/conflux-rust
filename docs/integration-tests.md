# Integration Tests

The Conflux-rust integration tests are written in Python. Currently, there are two versions of the tests located in the `tests` and `integration_tests` directories. All files in these directories with filenames containing `test` are test cases.

The second version refactors the first, making the tests more modular, easier to maintain, and introducing the pytest testing framework.

The integration tests primarily focus on:

- Verifying the correctness of the consensus algorithm
- Ensuring the implementation of each CIP meets the expected specifications
- Validating the correctness of RPC interfaces

## test_framework

The `test_framework` directory contains a blockchain testing framework evolved from Bitcoin's testing framework. This framework allows for setting up a multi-node local test network as needed and provides common blockchain control methods such as block generation, data synchronization, and node termination.

Additionally, the framework offers commonly used testing infrastructure:

- RPC Client
- SDK instantiation
- Commonly used contracts
- Accounts with preloaded balances

## Conflux Utils

The `conflux` directory includes utilities for common blockchain interactions, such as:

- Address conversion
- RPC and pubsub
- Transaction definitions
- Type conversions
- Encoding/decoding

## Contracts

Integration tests require some contracts, primarily located in:

- `tests/contracts`: Solidity code and the corresponding ABI and bytecode files compiled using native compilers.
- `tests/test_contracts`: A Hardhat project containing Solidity files and compiled artifact files ready for use. This directory is a git submodule, with its repository hosted at [conflux-chain/conflux-rust-dev-contracts](https://github.com/Conflux-Chain/conflux-rust-dev-contracts.git).

## SDK

- In version 1 of the integration tests, the Ethereum Python SDK, web3.py, was partially used.
- In version 2, SDKs are extensively used to write test cases. Core Space uses [python-conflux-sdk](https://github.com/Conflux-Chain/python-conflux-sdk), while eSpace uses [web3.py](https://web3py.readthedocs.io/en/stable/index.html).

## Miscellaneous

### Submodules

The integration test framework depends on two git submodules:

- `conflux-rust-dev-contracts`: Contract code
- `extra-test-toolkits`: For consensus and fuzzing tests

Use the following command to fetch the submodule code:

```sh
git submodule update --remote --recursive --init
```

### Node Program

Before running the tests, you must compile the node program. Refer to the [README.md](../README.md) for compilation instructions.

### Running Version 1 Integration Tests

Run all tests:

```sh
python3 tests/test_all.py
```

Run a specific test:

```sh
python3 tests/erc20_test.py
```

### Writing Integration Test Cases

It is recommended to write test cases using the newer version. Older test cases will be gradually migrated. Refer to [integration_tests/readme](../integration_tests/readme.md) for detailed instructions on writing test cases.