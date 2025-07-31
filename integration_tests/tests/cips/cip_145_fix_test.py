import pytest
from typing import Type
from integration_tests.test_framework.test_framework import FrameworkOptions
from integration_tests.tests.conftest import ConfluxTestFramework
from cfx_utils import CFX
from conflux_web3 import Web3

STORAGE_COLLATERAL = 62500000000000000

class BaseTestEnv(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["public_evm_rpc_apis"] = '"all"'
        self.conf_parameters["executive_trace"] = "true"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])

# class CIP145FixTestEnv(BaseTestEnv):
#     def set_test_params(self):
#         super().set_test_params()

class CIP145TestEnv(BaseTestEnv):
    def set_test_params(self):
        super().set_test_params()
        # disable V3.0 hardfork (CIP-145-fix)
        self.conf_parameters["eoa_code_transition_height"] = 99999999

class CIP78TestEnv(BaseTestEnv):
    def set_test_params(self):
        super().set_test_params()
        # disable V2.4 hardfork(CIP-145)
        self.conf_parameters["base_fee_burn_transition_number"] = 99999999
        self.conf_parameters["base_fee_burn_transition_height"] = 99999999
        # disable V3.0 hardfork (CIP-145-fix)
        self.conf_parameters["eoa_code_transition_height"] = 99999999

class OriginTestEnv(BaseTestEnv):
    def set_test_params(self):
        super().set_test_params()
        # disable CIP-78b
        self.conf_parameters["cip78_patch_transition_number"] = 99999999
        # disable V2.4 hardfork (CIP-145)
        self.conf_parameters["base_fee_burn_transition_number"] = 99999999
        self.conf_parameters["base_fee_burn_transition_height"] = 99999999
        # disable V3.0 hardfork (CIP-145-fix)
        self.conf_parameters["eoa_code_transition_height"] = 99999999


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
    contract = network.deploy_contract("Receivable", {
        "gasPrice": 1,
    })
    contract_address = contract.address
    sponsor_whitelist_control = network.internal_contract("SponsorWhitelistControl")
    
    # contract_addr, upperbound
    sponsor_whitelist_control.functions.setSponsorForGas(contract_address, 10 ** 9).transact({
        "value": CFX(1),
        "gasPrice": 1,
    }).executed()
    sponsor_whitelist_control.functions.addPrivilegeByAdmin(contract_address, [network.cw3.address.zero_address()]).transact(
        {
            "gasPrice": 1,
        }
    ).executed()
    return contract

def fund_new_account(cw3: Web3, value: int):
    account = cw3.cfx.account.create()
    cw3.wallet.add_account(account)
    cw3.cfx.send_transaction({
        "value": value,
        "to": account.address,
        "gasPrice": 1
    }).executed()
    return account

def send_raw_failed_transaction_executed(network, raw_tx):
    # with pytest.raises(Web3RPCError) as e:
    #     network.cw3.cfx.send_raw_transaction(raw_tx.raw_transaction)
    # assert "is discarded due to out of balance" in e.value.message 
    
    latest_block = network.cw3.cfx.get_block("latest_mined")
    new_block_hash = network.client.generate_custom_block(latest_block["hash"].to_0x_hex(), [], [raw_tx])
    parent_block = new_block_hash
    for _ in range(10):
        parent_block = network.client.generate_block_with_parent(parent_block, num_txs=1)
    
    transaction_hash = raw_tx.hash
    return network.cw3.cfx.get_transaction_receipt(transaction_hash)

@pytest.mark.parametrize("framework_class", [
    OriginTestEnv,
    CIP78TestEnv,
    CIP145TestEnv,
    # CIP145FixTestEnv
])
def test_success_behaviour(network, gas_sponsored_contract):
    network.client.generate_blocks_to_state()
    cw3 = network.cw3
    assert network.internal_contract("SponsorWhitelistControl").functions.isAllWhitelisted(gas_sponsored_contract.address).call()
    sender = fund_new_account(cw3, STORAGE_COLLATERAL)
    
    raw_tx = sender.sign_transaction({
        "to": gas_sponsored_contract.address,
        "value": 0,
        "from": sender.address,
        "chainId": network.cw3.cfx.chain_id,
        "gas": 30000,
        "gasPrice": 1,
        "storageLimit": 64,
        "epochHeight": 10,
        "nonce": 0,
    })
    receipt = cw3.cfx.send_raw_transaction(raw_tx.raw_transaction).executed()
    assert receipt["gasCoveredBySponsor"]

@pytest.mark.parametrize("framework_class,expected_sponsor_flag", 
                         [(OriginTestEnv, False),
                          (CIP78TestEnv, True),
                          (CIP145TestEnv, True), 
                        #   (CIP145FixTestEnv, False)
                          ]
                         )
def test_not_enough_balance_behaviour(network, gas_sponsored_contract, expected_sponsor_flag):
    cw3 = network.cw3
    # ensure hardfork transition number
    network.client.generate_blocks_to_state()
    assert network.internal_contract("SponsorWhitelistControl").functions.isAllWhitelisted(gas_sponsored_contract.address).call()
    sender = fund_new_account(cw3, 50000)
    
    before_balance = cw3.cfx.get_balance(sender.address)

    raw_tx = sender.sign_transaction({
        "to": gas_sponsored_contract.address,
        "value": 0,
        "from": sender.address,
        "chainId": network.cw3.cfx.chain_id,
        "gas": 30000,
        "gasPrice": 1,
        "storageLimit": 64,
        "epochHeight": 10,
        "nonce": 0,
    })
    
    receipt = send_raw_failed_transaction_executed(network, raw_tx)
    after_balance = cw3.cfx.get_balance(sender.address)
    
    # Gas is not covered by sponsor actually
    assert after_balance < before_balance
    assert "NotEnoughCash" in receipt["txExecErrorMsg"]
    assert receipt["gasCoveredBySponsor"] == expected_sponsor_flag
    

@pytest.mark.parametrize("framework_class,expected_sponsor_flag", 
                         [(OriginTestEnv, False),
                          (CIP78TestEnv, True),
                          (CIP145TestEnv, False), 
                        #   (CIP145FixTestEnv, True)
                          ])
def test_out_of_gas_behaviour(network, gas_sponsored_contract, expected_sponsor_flag):
    cw3 = network.cw3
    # ensure hardfork transition number
    network.client.generate_blocks_to_state()
    assert network.internal_contract("SponsorWhitelistControl").functions.isAllWhitelisted(gas_sponsored_contract.address).call()
    
    # Ensure sufficient funds so the transaction does not fail due to insufficient balance for storage collateral.
    sender = fund_new_account(cw3, STORAGE_COLLATERAL + 50000)
    
    before_balance = cw3.cfx.get_balance(sender.address)

    raw_tx = sender.sign_transaction({
        "to": gas_sponsored_contract.address,
        "value": 0,
        "from": sender.address,
        "chainId": network.cw3.cfx.chain_id,
        "gas": 22000,
        "gasPrice": 1,
        "storageLimit": 64,
        "epochHeight": 10,
        "nonce": 0,
    })
    receipt = send_raw_failed_transaction_executed(network, raw_tx)
    after_balance = cw3.cfx.get_balance(sender.address)
    
    # Gas is not covered by sponsor
    assert after_balance == before_balance
    assert "OutOfGas" in receipt["txExecErrorMsg"]
    assert receipt["gasCoveredBySponsor"] == expected_sponsor_flag    
