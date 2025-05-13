import pytest
from ethereum_test_forks.forks.forks import Prague
from integration_tests.test_framework.test_framework import ConfluxTestFramework

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


MIN_NATIVE_BASE_PRICE = 10000
# set to 1 because this is the chain id of ethereum execution spec tests
EVM_CHAIN_ID = 1

@pytest.fixture(scope="module")
def framework_class():
    class EIP7702TestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["evm_chain_id"] = str(EVM_CHAIN_ID)
            self.conf_parameters["eoa_code_transition_height"] = 1
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["align_evm_transition_height"] = 1

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])

    return EIP7702TestEnv
