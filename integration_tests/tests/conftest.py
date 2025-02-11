from conflux_web3 import Web3
import pytest
import argparse
import os
from typing import Type
from eth_utils import decode_hex

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.rpc import RpcClient
from web3.tracing import Tracing

TMP_DIR = None

PORT_MIN = 11000
PORT_MAX = 65535
PORT_RANGE = 100

@pytest.fixture(scope="session")
def arg_parser():
    parser = argparse.ArgumentParser(usage="%(prog)s [options]")
    parser.add_argument(
        "--nocleanup",
        dest="nocleanup",
        default=False,
        action="store_true",
        help="Leave bitcoinds and test.* datadir on exit or error")
    parser.add_argument(
        "--noshutdown",
        dest="noshutdown",
        default=False,
        action="store_true",
        help="Don't stop bitcoinds after the test execution")
    parser.add_argument(
        "--cachedir",
        dest="cachedir",
        default=os.path.abspath(
            os.path.dirname(os.path.realpath(__file__)) + "/../../cache"),
        help=
        "Directory for caching pregenerated datadirs (default: %(default)s)"
    )
    parser.add_argument(
        "--tmpdir", dest="tmpdir", help="Root directory for datadirs")
    parser.add_argument(
        "-l",
        "--loglevel",
        dest="loglevel",
        default="INFO",
        help=
        "log events at this level and higher to the console. Can be set to DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG will output all logs to console. Note that logs at all levels are always written to the test_framework.log file in the temporary test directory."
    )
    parser.add_argument(
        "--tracerpc",
        dest="trace_rpc",
        default=False,
        action="store_true",
        help="Print out all RPC calls as they are made")
    parser.add_argument(
        "--portseed",
        dest="port_seed",
        default=os.getpid(),
        type=int,
        help=
        "The seed to use for assigning port numbers (default: current process id)"
    )
    parser.add_argument(
        "--coveragedir",
        dest="coveragedir",
        help="Write tested RPC commands into this directory")
    parser.add_argument(
        "--pdbonfailure",
        dest="pdbonfailure",
        default=False,
        action="store_true",
        help="Attach a python debugger if test fails")
    parser.add_argument(
        "--usecli",
        dest="usecli",
        default=False,
        action="store_true",
        help="use bitcoin-cli instead of RPC for all commands")
    parser.add_argument(
        "--randomseed",
        dest="random_seed",
        type=int,
        help="Set a random seed")
    parser.add_argument(
        "--metrics-report-interval-ms",
        dest="metrics_report_interval_ms",
        default=0,
        type=int)

    parser.add_argument(
        "--conflux-binary",
        dest="conflux",
        default=os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "../../target/release/conflux"),
        type=str)
    parser.add_argument(
        "--port-min",
        dest="port_min",
        default=11000,
        type=int)
    return parser

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
def network(framework_class: Type[ConfluxTestFramework], port_min: int, additional_secrets: int, request: pytest.FixtureRequest):
    try:
        framework = framework_class(port_min, additional_secrets)
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
def receiver_account(ew3):
    return ew3.eth.account.create()
