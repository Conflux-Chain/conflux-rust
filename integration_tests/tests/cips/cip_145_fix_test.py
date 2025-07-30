import pytest
from typing import Type
from integration_tests.test_framework.test_framework import FrameworkOptions
from integration_tests.tests.conftest import ConfluxTestFramework
from cfx_utils import CFX
from conflux_web3 import Web3
from web3.exceptions import Web3RPCError


class CIP145BeforeFixTestEnv(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["eoa_code_transition_height"] = 1
        self.conf_parameters["cip151_transition_height"] = 1
        self.conf_parameters["cip645_transition_height"] = 1
        self.conf_parameters["public_evm_rpc_apis"] = '"all"'
        self.conf_parameters["executive_trace"] = "true"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        
class CIP145AfterFixTestEnv(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["eoa_code_transition_height"] = 1
        self.conf_parameters["cip151_transition_height"] = 1
        self.conf_parameters["cip645_transition_height"] = 1
        self.conf_parameters["cip145_fix_transition_height"] = 1
        self.conf_parameters["public_evm_rpc_apis"] = '"all"'
        self.conf_parameters["executive_trace"] = "true"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])  


# copied from integration_tests/tests/conftest.py to overide fixture scope
@pytest.fixture
def network(framework_class: Type[ConfluxTestFramework], port_min: int, additional_secrets: int, args: FrameworkOptions, request: pytest.FixtureRequest):
    try:
        framework = framework_class(port_min, additional_secrets, options=args)
    except Exception as e:
        pytest.fail(f"Failed to setup framework: {e}")
    yield framework
    framework.teardown(request)
    
@pytest.fixture
def gas_sponsored_contract(network):
    contract = network.deploy_contract("Receivable")
    contract_address = contract.address
    sponsor_whitelist_control = network.internal_contract("SponsorWhitelistControl")
    
    # contract_addr, upperbound
    sponsor_whitelist_control.functions.setSponsorForGas(contract_address, 10 ** 9).transact({
        "value": CFX(1)
    }).executed()
    sponsor_whitelist_control.functions.addPrivilegeByAdmin(contract_address, [network.cw3.address.zero_address()]).transact().executed()
    return contract

def fund_new_account(cw3: Web3, value: int):
    account = cw3.cfx.account.create()
    cw3.wallet.add_account(account)
    cw3.cfx.send_transaction({
        "value": value,
        "to": account.address,
    }).executed()
    return account

@pytest.mark.parametrize("framework_class", [CIP145BeforeFixTestEnv, CIP145AfterFixTestEnv])
def test_value_enough_behaviour(network, gas_sponsored_contract):
    network.client.generate_blocks_to_state()
    cw3 = network.cw3
    assert network.internal_contract("SponsorWhitelistControl").functions.isAllWhitelisted(gas_sponsored_contract.address).call()
    sender = fund_new_account(cw3, 100000)

    raw_tx = sender.sign_transaction({
        "to": gas_sponsored_contract.address,
        "value": 100000,
        "from": sender.address,
        "chainId": network.cw3.cfx.chain_id,
        "gas": 30000,
        "gasPrice": 1,
        "storageLimit": 0,
        "epochHeight": 10,
        "nonce": 0,
    })
    receipt = cw3.cfx.send_raw_transaction(raw_tx.raw_transaction).executed()
    assert receipt["gasCoveredBySponsor"]

@pytest.mark.parametrize("framework_class", [CIP145BeforeFixTestEnv, CIP145AfterFixTestEnv])
def test_cip145_activated_behaviour(network, gas_sponsored_contract):
    cw3 = network.cw3
    # ensure hardfork transition number
    network.client.generate_blocks_to_state()
    assert network.internal_contract("SponsorWhitelistControl").functions.isAllWhitelisted(gas_sponsored_contract.address).call()
    sender = fund_new_account(cw3, 100000)

    raw_tx = sender.sign_transaction({
        "to": gas_sponsored_contract.address,
        "value": 100001,
        "from": sender.address,
        "chainId": network.cw3.cfx.chain_id,
        "gas": 30000,
        "gasPrice": 1,
        "storageLimit": 0,
        "epochHeight": 10,
        "nonce": 0,
    })
    with pytest.raises(Web3RPCError) as e:
        cw3.cfx.send_raw_transaction(raw_tx.raw_transaction)
    assert "is discarded due to out of balance, needs 100001 but account balance is 100000" in e.value.message 
    
    latest_block = network.cw3.cfx.get_block("latest_mined")
    new_block_hash = network.client.generate_custom_block(latest_block["hash"].to_0x_hex(), [], [raw_tx])
    parent_block = new_block_hash
    for _ in range(10):
        parent_block = network.client.generate_block_with_parent(parent_block, num_txs=1)
    
    transaction_hash = raw_tx.hash
    transaction_receipt = network.cw3.cfx.get_transaction_receipt(transaction_hash)
    assert transaction_receipt["txExecErrorMsg"]== 'NotEnoughCash { required: 100001, got: 100000, actual_gas_cost: 30000, max_storage_limit_cost: 0 }'
    assert not transaction_receipt["gasCoveredBySponsor"]
    
    
    
