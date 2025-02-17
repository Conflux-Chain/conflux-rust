from conflux_web3 import Web3
import pytest
import os
from typing import Type

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.test_framework import FrameworkOptions
from web3.tracing import Tracing

TMP_DIR = None

PORT_MIN = 11000
PORT_MAX = 65535
PORT_RANGE = 100

# pytest hook to add options
def pytest_addoption(parser):
    parser.addoption(
        "--conflux-nocleanup",
        dest="nocleanup",
        default=False,
        action="store_true",
        help="Leave bitcoinds and test.* datadir on exit or error")
    parser.addoption(
        "--conflux-noshutdown",
        dest="noshutdown",
        default=False,
        action="store_true",
        help="Don't stop bitcoinds after the test execution")
    parser.addoption(
        "--conflux-cachedir",
        dest="cachedir",
        default=os.path.abspath(
            os.path.dirname(os.path.realpath(__file__)) + "/../../cache"),
        help=
        "Directory for caching pregenerated datadirs (default: %(default)s)"
    )
    parser.addoption(
        "--conflux-tmpdir", dest="tmpdir", help="Root directory for datadirs")
    parser.addoption(
        "--conflux-loglevel",
        dest="loglevel",
        default="INFO",
        help=
        "log events at this level and higher to the console. Can be set to DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG will output all logs to console. Note that logs at all levels are always written to the test_framework.log file in the temporary test directory."
    )
    parser.addoption(
        "--conflux-tracerpc",
        dest="trace_rpc",
        default=False,
        action="store_true",
        help="Print out all RPC calls as they are made")
    parser.addoption(
        "--conflux-portseed",
        dest="port_seed",
        default=os.getpid(),
        type=int,
        help=
        "The seed to use for assigning port numbers (default: current process id)"
    )
    parser.addoption(
        "--conflux-coveragedir",
        dest="coveragedir",
        help="Write tested RPC commands into this directory")
    parser.addoption(
        "--conflux-pdbonfailure",
        dest="pdbonfailure",
        default=False,
        action="store_true",
        help="Attach a python debugger if test fails")
    parser.addoption(
        "--conflux-usecli",
        dest="usecli",
        default=False,
        action="store_true",
        help="use bitcoin-cli instead of RPC for all commands")
    parser.addoption(
        "--conflux-randomseed",
        dest="random_seed",
        type=int,
        help="Set a random seed")
    parser.addoption(
        "--conflux-metrics-report-interval-ms",
        dest="metrics_report_interval_ms",
        default=0,
        type=int)

    parser.addoption(
        "--conflux-binary",
        dest="conflux",
        default=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "../../target/release/conflux"),
        type=str)
    parser.addoption(
        "--conflux-port-min",
        dest="port_min",
        default=0,
        type=int)  # only used if set to bigger than 0

def get_args_from_request(request: pytest.FixtureRequest) -> FrameworkOptions:
    return FrameworkOptions(
        nocleanup=request.config.getoption("nocleanup"),  # type: ignore
        noshutdown=request.config.getoption("noshutdown"),  # type: ignore
        cachedir=request.config.getoption("cachedir"),  # type: ignore
        tmpdir=request.config.getoption("tmpdir"),  # type: ignore
        loglevel=request.config.getoption("loglevel"),  # type: ignore
        trace_rpc=request.config.getoption("trace_rpc"),  # type: ignore
        coveragedir=request.config.getoption("coveragedir"),  # type: ignore
        pdbonfailure=request.config.getoption("pdbonfailure"),  # type: ignore
        usecli=request.config.getoption("usecli"),  # type: ignore
        random_seed=request.config.getoption("random_seed"),  # type: ignore
        metrics_report_interval_ms=request.config.getoption("metrics_report_interval_ms"),  # type: ignore
        conflux=request.config.getoption("conflux"), # type: ignore
        port_min=request.config.getoption("port_min"),  # type: ignore
    )
    
@pytest.fixture(scope="session")
def args(request: pytest.FixtureRequest) -> FrameworkOptions:
    return get_args_from_request(request)

@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])
    return DefaultFramework

@pytest.fixture(scope="module")
def network(framework_class: Type[ConfluxTestFramework], port_min: int, additional_secrets: int, args: FrameworkOptions, request: pytest.FixtureRequest):
    try:
        framework = framework_class(port_min, additional_secrets, options=args)
    except Exception as e:
        pytest.fail(f"Failed to setup framework: {e}")
    yield framework
    framework.teardown(request)
    
@pytest.fixture(scope="module")
def port_min(worker_id: str) -> int:
    # worker_id is "master" or "gw0", "gw1", etc.
    index = int(worker_id.split("gw")[1]) if "gw" in worker_id else 0
    return PORT_MIN + index * PORT_RANGE

@pytest.fixture(scope="module")
def additional_secrets():
    return 0

@pytest.fixture(scope="module")
def cw3(network: ConfluxTestFramework):
    return network.cw3

@pytest.fixture(scope="module")
def ew3(network: ConfluxTestFramework) -> Web3:
    return network.ew3

@pytest.fixture(scope="module")
def ew3_tracing(ew3): 
    tracing: 'Tracing' = ew3.tracing
    return tracing

@pytest.fixture(scope="module")
def core_accounts(network: ConfluxTestFramework):
    return network.core_accounts

@pytest.fixture(scope="module")
def evm_accounts(network: ConfluxTestFramework):
    return network.evm_accounts

@pytest.fixture(scope="module")
def internal_contracts(network: ConfluxTestFramework):
    return {
        "AdminControl": network.internal_contract("AdminControl"),
        "SponsorWhitelistControl": network.internal_contract("SponsorWhitelistControl"),
        "Staking": network.internal_contract("Staking"),
        "ConfluxContext": network.internal_contract("ConfluxContext"),
        "PoSRegister": network.internal_contract("PoSRegister"),
        "CrossSpaceCall": network.internal_contract("CrossSpaceCall"),
        "ParamsControl": network.internal_contract("ParamsControl"),
    }

