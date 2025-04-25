# evm

The `evm-spec-tester` command is primarily used to run tests related to the Ethereum Virtual Machine (EVM), in order to verify the compatibility of the Conflux eSpace VM.

Currently, it supports one type of tests: `statetest`.

## statetest

The state tests is used to test the state transition function of the Ethereum Virtual Machine (EVM).

It does so by defining a transaction, a pre-execution state, and a post-execution state, and verifying that the transaction execution results in the expected post-execution state. [`pointer_reentry.json`](./pointer_reentry.json) is an example of a state test case.

Check more details in the [execution-spec-tests documentation](https://eest.ethereum.org/main/consuming_tests/state_test/)

### How to get the statetest fixtures

Statetest fixtures are mainly located in two Ethereum-related testing repositories.: [`execution-spec-tests`](https://github.com/ethereum/execution-spec-tests) and [`tests`](https://github.com/ethereum/tests).

#### execution-spec-tests

`execution-spec-tests` has been in development since Q4 2022. It serves as a testing framework and test suite primarily for Ethereum execution clients, and includes various types of test cases such as state tests, blockchain tests, EOF tests, transaction tests, and more.

The releases of this repository include pre-generated test cases in JSON format, which can be directly downloaded and used. Each version release contains two artifacts:

- `fixtures_stable.tar.gz`: All tests until the last stable fork ("must pass")
- `fixtures_develop.tar.gz`: All tests until the last development fork

These two artifacts correspond to test cases for the stable (mainnet) version and the development version, respectively. After extraction, the JSON files located in the `state_tests` directory are the state test cases.

#### tests

The `tests` repository is another Ethereum testing repo that also includes state test cases. You can obtain these state tests by downloading the `fixtures_general_state_tests.tgz` archive from the releases.

Alternatively, you can clone the repository locally. The `GeneralStateTests` directory in the project contains the state test cases. Additionally, the `legacytests/Constantinople/GeneralStateTests` directory also includes some legacy state test cases.

### How to run the statetest

You can run the evm statetest command and specify the directory containing the state test cases to execute the tests:

```bash
evm-spec-tester -c ./evm-config.toml /data/test-fixtures/develop/state_tests/prague
```

#### run single test

If you only want to run a single test file, you can use the --match parameter to specify the name of the test file:

```bash
evm-spec-tester -c ./evm-config.toml /data/test-fixtures/develop/state_tests/prague --matches the-test-file-name.json
```

#### verbose mode

You can enable verbose mode by using -v or -vv. In this mode, more debug information will be printed, such as:

```bash
evm-spec-tester -c ./evm-config.toml /data/test-fixtures/develop/state_tests/prague --matches the-test-file-name.json -vv
```

#### configuration

The `evm-config.toml` file is a configuration file used to control the behavior of the Conflux node, such as which CIPs (Conflux Improvement Proposals) are enabled. 

Below is a sample configuration file, where all CIPs are activated at block height 1:

```yaml
mode="dev"
default_transition_time=1
pos_reference_enable_height=1
cip43_init_end_number=1
align_evm_transition_height=1
cip112_transition_height=1 # block custom field encoding
tanzanite_transition_height=1 # change block reward from 7 to 2
chain_id=2
evm_chain_id=1
```

If no configuration file is specified, the default activation settings (same as the mainnet) will be used.

### Skiped tests

Some tests are skipped due to conflux does not support some features of the EVM. The skipped tests are listed below:

- EIP-4844 tests
- EOF tests