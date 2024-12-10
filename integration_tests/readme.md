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

#### VSCode

Put the below configuration in `.vscode/settings.json`:

```json
{
    "python.testing.pytestArgs": [
        "integration_tests/tests",
        "-vv",
        "-n", "logical",
        "--dist", "loadscope",
    ],
    "python.testing.unittestEnabled": false,
    "python.testing.pytestEnabled": true
}
```

Then you can see the tests in VSCode test explorer. You can run tests by clicking the test name.

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
