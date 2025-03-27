import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import load_contract_metadata
from integration_tests.conflux.rpc import RpcClient
from hexbytes import HexBytes
from web3 import Web3
from typing import Type, TypedDict
from web3.types import TxReceipt


@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1
            self.conf_parameters["public_evm_rpc_async_apis"] = "\"all\"" # open all async apis
            self.conf_parameters["public_evm_rpc_apis"] = (
                '"eth,ethdebug"'
            )
            # self.conf_parameters["evm_chain_id"] = str(10)
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)
            self.conf_parameters["executive_trace"] = "true"

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])

    return DefaultFramework


@pytest.fixture(scope="module", params=["ew3_port_v1", "ew3_port_v2"])
def ew3(network: ConfluxTestFramework, request):
    if request.param == "ew3_port_v2":
        return network.ew3
    else:
        return network._legacy_ew3

@pytest.fixture(scope="module")
def erc20_contract(ew3, evm_accounts):
    account = evm_accounts[0]
    contract_meta = load_contract_metadata("MyToken")
    # deploy contract
    TokenContract = ew3.eth.contract(
        abi=contract_meta["abi"], bytecode=contract_meta["bytecode"]
    )
    tx_hash = TokenContract.constructor(account.address).transact()
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    # create erc20 contract instance
    deploy_receipt = ew3.eth.get_transaction_receipt(tx_hash)
    assert deploy_receipt["status"] == 1
    erc20_address = deploy_receipt["contractAddress"]

    token_contract = ew3.eth.contract(address=erc20_address, abi=contract_meta["abi"])

    # mint 100 tokens to creator
    mint_hash = token_contract.functions.mint(
        account.address, ew3.to_wei(100, "ether")
    ).transact()
    ew3.eth.wait_for_transaction_receipt(mint_hash)

    return {
        "contract": token_contract,
        "deploy_hash": tx_hash,
    }

class ERC20TransferResult(TypedDict):
    tx_hash: HexBytes
    receipt: TxReceipt

@pytest.fixture(scope="module")
def erc20_token_transfer(erc20_contract, ew3: Web3) -> ERC20TransferResult:
    to_address = ew3.eth.account.create().address
    token_contract = erc20_contract["contract"]
    transfer_hash = token_contract.functions.transfer(
        to_address, ew3.to_wei(1, "ether")
    ).transact()
    receipt: TxReceipt = ew3.eth.wait_for_transaction_receipt(transfer_hash)
    return {
        "tx_hash": transfer_hash,
        "receipt": receipt,
    }

@pytest.fixture(scope="module")
def receiver_account(ew3):
    return ew3.eth.account.create()