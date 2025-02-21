# Conflux Rust Integration Tests

## Folder Structure

- `integration_tests/conflux`, `integration_tests/test_framework`: util or framework code required by tests.
- `integration_tests/tests`: code for integration tests.

## Setup

> Suppose rust binary is built, refer to [README.md](../README.md) for more details.

### Python Environment Setup

It is recommended to run tests under a virtual environment. For example, use `venv` or `conda` to create a virtual environment.

Use `venv` to create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Use `conda` to create a virtual environment:

```bash
conda create -n conflux_test python=3.10
conda activate conflux_test
```

### Python Dependencies

Use `dev-support/dep_pip3.sh` to install python dependencies.

```bash
./dev-support/dep_pip3.sh
```

### Run Tests

#### Command Line

Run tests with `pytest`:

```bash
pytest integration_tests/tests -vv -n logical --dist loadscope
```

> `-vv` is to show more logs.
> 
> `-n logical` is to run tests in parallel. You can replace `logical` with `2` or more to run tests in parallel with the specified number of processes.
> 
> `--dist loadscope` controls how tests are distributed. The provided configuration groups tests by their scope—functions within the same module or methods within the same test class—and assigns each group to a single worker.

Use pytest options to filter tests:

```bash
pytest integration_tests/tests -k test_name

# or 

pytest integration_tests/tests/test_file.py::test_name

# Run tests in a specific file
pytest integration_tests/tests/test_file.py

# Run tests in a specific class
pytest integration_tests/tests/test_file.py::test_name

# Arguments for ConfluxTestFramework also supported
# argument explanations can be found in integration_tests/tests/conftest.py::pytest_addoption
pytest integration_tests/tests/example_test.py -s --conflux-nocleanup
```

#### VSCode

Put the below configuration in `.vscode/settings.json`:

```json
{
    "python.testing.pytestArgs": [
        "integration_tests/tests",
        "-vv",  // show more logs
        "-s", // show the print statements in the test
        // "-n", "logical", // run tests in parallel
        // "--dist", "loadscope", // tests are grouped by module(single python file)
    ],
    "python.testing.unittestEnabled": false,
    "python.testing.pytestEnabled": true
}
```

Then you can see the tests in VSCode test explorer. You can run tests by clicking the test name.

> `-n` and `--dist` are commented out by default. You can uncomment them to run tests in parallel.
> But it should note that if you run tests in parallel, the test logs will be hidden by default.

## Add New Tests

### Fixture Configuration

Pytest fixtures are something setup before tests are run. You can find fixtures in the test files as well as `*/conftest.py`. 

> Refer to [pytest documentation](https://docs.pytest.org/en/latest/how-to/fixtures.html) for more details.

In [global conftest.py](./tests/conftest.py), the `framework_class` fixture and `network` fixture are defined for the test framework setup.

```python

@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters = {
                "executive_trace": "true",
                "public_rpc_apis": "\"cfx,debug,test,pubsub,trace\"",
                # Disable 1559 for RPC tests temporarily
                "cip1559_transition_height": str(99999999),
            }
        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])
    return DefaultFramework

@pytest.fixture(scope="module")
def network(framework_class: Type[ConfluxTestFramework], port_min: int, request: pytest.FixtureRequest):
    try:
        framework = framework_class(port_min)
    except Exception as e:
        pytest.fail(f"Failed to setup framework: {e}")
    yield framework
    framework.teardown(request)
```

In the tests, you can start by directly using the `network` fixture for the test framework setup.

You can overwrite the `framework_class` fixture in the test file to customize the test framework setup. Check [cip137_test.py](./tests/cip137_test.py) for an example.

#### Common Fixtures

Basic Fixtures:

1. **`framework_class`**: The test framework class used to configure test parameters and start the test network. If a custom test framework (e.g., with specific parameters) is needed, this fixture can be overridden.  
2. **`network`**: An instance of the `framework_class`.

Core Space Fixtures:

1. **`cw3`**: An instance of `python-conflux-sdk`.  
2. **`core_accounts`**: Core Space accounts with a predefined CFX balance, ready for sending transactions.  
3. **`client`**: An instance of [`RpcClient`](./conflux/rpc.py) that wraps Core Space RPC interfaces for easier usage.

eSpace Fixtures:

1. **`ew3`**: An instance of `web3.py`.  
2. **`evm_accounts`**: eSpace accounts with a predefined CFX balance, ready for sending transactions.  

### Add tests

Create a new test file in the `tests` directory. The filename must include `test`, for example, `my_test.py`. Then, add test methods in the file with names that include `test`.

```python
def test_hello():
    assert True
```

## FAQs
