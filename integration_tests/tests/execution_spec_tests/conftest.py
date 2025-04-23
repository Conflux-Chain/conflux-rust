import pytest
import time

from functools import partial
from web3 import Web3

from ethereum_test_tools import (
    Environment,
)
from ethereum_test_forks.helpers import get_closest_fork_with_solc_support
from ethereum_test_forks import Fork
from ethereum_test_forks.forks.forks import Prague
from ethereum_test_tools.code import Yul

from integration_tests.test_framework.test_framework import ConfluxTestFramework, AutoTraceMiddleware
from integration_tests.test_framework.util.adapter import AllocMock, conflux_state_test

def pytest_configure(config):
    """Register the with_all_call_opcodes marker"""
    config.addinivalue_line(
        "markers", "with_all_call_opcodes: Parameterize tests with all call opcodes"
    )
    config.addinivalue_line(
        "markers", "with_all_create_opcodes: Parameterize tests with all create opcodes"
    )
    config.addinivalue_line(
        "markers", "with_all_precompiles: Parameterize tests with all precompiles"
    )

@pytest.fixture(scope="module")
def state_test(ew3: Web3, network: ConfluxTestFramework):
    # Use functools.partial to curry the function with ew3 and network parameters
    return partial(conflux_state_test, ew3, network)

@pytest.fixture(scope="module")
def blockchain_test(ew3: Web3, network: ConfluxTestFramework):
    return partial(conflux_state_test, ew3, network, env=Environment())

@pytest.fixture(scope="module")
def pre(ew3, evm_accounts):
    return AllocMock(ew3, evm_accounts[-1])

@pytest.fixture
def solc_version():
    return "0.8.24"

@pytest.fixture
def yul(fork: Fork, solc_version: str):
    
    solc_version = get_closest_fork_with_solc_support(fork, solc_version)

    class YulWrapper(Yul):
        def __new__(cls, *args, **kwargs):
            return super(YulWrapper, cls).__new__(cls, *args, **kwargs, fork=solc_version)

    return YulWrapper


MIN_NATIVE_BASE_PRICE = 10000
# set to 1 because this is the chain id of ethereum execution spec tests
EVM_CHAIN_ID = 1


@pytest.fixture(scope="module")
def fork():
    return Prague

def pytest_generate_tests(metafunc):
    """Parameterize tests based on opcode-related markers"""
    
    def _parameterize_opcodes(metafunc, marker_name: str, opcodes: list, fixture_names: list[str]):
        """Helper to handle opcode parameterization logic"""
        if metafunc.definition.get_closest_marker(marker_name):
            if all(f in metafunc.fixturenames for f in fixture_names):
                metafunc.parametrize(",".join(fixture_names), opcodes)
            else:
                for i, fixture in enumerate(fixture_names):
                    if fixture in metafunc.fixturenames:
                        metafunc.parametrize(fixture, [opcode[i] if len(fixture_names) > 1 else opcode for opcode in opcodes])

    # Handle call opcode parameterization
    _parameterize_opcodes(
        metafunc,
        "with_all_call_opcodes",
        Prague.call_opcodes(),
        ["call_opcode", "evm_code_type"]
    )
    
    # Handle create opcode parameterization
    _parameterize_opcodes(
        metafunc,
        "with_all_create_opcodes", 
        Prague.create_opcodes(),
        ["create_opcode", "evm_code_type"]
    )
    
    _parameterize_opcodes(
        metafunc,
        "with_all_precompiles", 
        Prague.precompiles(),
        ["precompile"]
    )
    
    _parameterize_opcodes(
        metafunc,
        "with_all_system_contracts", 
        Prague.system_contracts(),
        ["precompile"]
    )



@pytest.fixture(scope="module")
def framework_class():
    class EIP7702TestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["evm_chain_id"] = str(EVM_CHAIN_ID)
            self.conf_parameters["eoa_code_transition_height"] = 1
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["align_evm_transition_height"] = 1
            self.conf_parameters["tx_pool_allow_gas_over_half_block"] = "true"
            self.conf_parameters["public_evm_rpc_apis"] = '"all"'
            self.conf_parameters["executive_trace"] = "true"

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])

    return EIP7702TestEnv


# The commented code is for testing if conflux's implementation 
# is compatible with anvil's implementation
@pytest.fixture(scope="module")
def web3_setting_pair(network, request, args, port_min):
    port = port_min + 99
    if args.use_anvil_for_spec_tests:
        from eth_account import Account as EthAccount
        EthAccount.enable_unaudited_hdwallet_features()
        from web3 import Web3
        from web3.middleware import SignAndSendRawMiddlewareBuilder
        # subprocess
        import subprocess
        p = subprocess.Popen(["anvil", "--port", str(port), "--hardfork", "Prague", "--chain-id", str(EVM_CHAIN_ID), "--steps-tracing", "--block-base-fee-per-gas", "1"], stdout=subprocess.DEVNULL)
        
        w3 = Web3(
            Web3.HTTPProvider(f"http://localhost:{port}")
        )
        retry = 0
        while not w3.is_connected() and retry < 5:
            time.sleep(0.1)
            retry += 1
        acct = EthAccount.from_mnemonic(
            "test test test test test test test test test test test junk",
            account_path="m/44'/60'/0'/0/0",
        )
        w3.eth.default_account = acct.address
        w3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(acct.key))
        if args.trace_tx:
            w3.middleware_onion.add(AutoTraceMiddleware)
        yield w3, acct
        p.terminate()
        p.wait()
    else:
        network.ew3.eth.default_account = network.evm_accounts[-1].address
        yield network.ew3, network.evm_accounts[-1]


@pytest.fixture(scope="module")
def ew3(web3_setting_pair):
    return web3_setting_pair[0]

@pytest.fixture(scope="module")
def evm_accounts(web3_setting_pair):
    return [web3_setting_pair[1]]