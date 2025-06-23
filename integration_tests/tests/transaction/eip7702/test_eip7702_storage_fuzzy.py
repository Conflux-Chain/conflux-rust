import pytest
from typing import Type, cast
from web3 import Web3
from web3.contract import Contract
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    sign_eip7702_transaction_with_default_fields,
)
from ethereum_test_tools import (
    Initcode,
    Opcodes as Op,
    Bytecode,
)
from dataclasses import dataclass
from enum import Enum
from itertools import product
import random
import time

@pytest.fixture(scope="module")
def contract_address(ew3: Web3, erc20_factory: Type[Contract]) -> str:
    tx_hash = erc20_factory.constructor(ew3.eth.default_account).transact()
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    return cast(str, receipt["contractAddress"])


def get_new_fund_account(ew3: Web3):
    new_account = ew3.eth.account.create()
    tx_hash = ew3.eth.send_transaction(
        {
            "to": new_account.address,
            "value": ew3.to_wei(1, "ether"),
        }
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    return new_account

def deploy_contract_using_deploy_code(ew3: Web3, deploy_code: Bytecode) -> str:
    initcode = Initcode(deploy_code=deploy_code)
    tx_hash = ew3.eth.send_transaction(
        {
            "data": bytes(initcode),
        }
    )
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    return cast(str, receipt["contractAddress"])


def assert_account_code_set_to_contract(
    ew3: Web3, account_address: str, contract_address: str
):
    code = ew3.eth.get_code(account_address)  # type: ignore
    assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()

STORAGE_SLOT_1 = 0x10
STORAGE_SLOT_2 = 0x20

class ContractSelection(Enum):
    """
    Enum for selecting which contract to use for authorization
    A: Use contract A
    B: Use contract B 
    RESET: Reset to zero code
    """
    A = "A"
    B = "B"
    RESET = "reset"

contract_a_expected_storage = {
    STORAGE_SLOT_1: 0x1,
    STORAGE_SLOT_2: 0x2
}

contract_b_expected_storage = {
    STORAGE_SLOT_1: 0x2,
    STORAGE_SLOT_2: 0x1
}

@dataclass
class StorageFuzzyOperation:
    call_when_auth: bool
    contract_selection: ContractSelection
    expected_storage: dict[int, int]
    
storage_fuzzy_operations = [
    StorageFuzzyOperation(
        call_when_auth=call_when_auth,
        contract_selection=contract_selection,
        expected_storage=contract_a_expected_storage if contract_selection == ContractSelection.A 
                        else contract_b_expected_storage if contract_selection == ContractSelection.B
                        else {}
    )
    for contract_selection, call_when_auth in product(
        [ContractSelection.A, ContractSelection.B, ContractSelection.RESET],
        [True, False]
    )
]

# Generate all possible combinations of 4 operations, allowing duplicates (6^4 = 1296 cases)
all_combinations_with_duplicates = list(product(storage_fuzzy_operations, repeat=4))

# Method 2: Randomly sample a subset of combinations to reduce test time
random.seed(time.time())
sampled_combinations = random.sample(all_combinations_with_duplicates, 20)  # Sample subset

# Choose which method to use (all or sampled)
operation_permutations = [list(comb) for comb in sampled_combinations]  # Use sampled subset with duplicates
# operation_permutations = [list(comb) for comb in all_combinations_with_duplicates]  # Use all combinations with duplicates

epoch_structures = [
    [1,1,1,1],
    [2,1,1],
    [1,2,1],
    [1,1,2],
    [2,2],
    [1,3],
    [3,1],
    [4],
]

@pytest.fixture(scope="module")
def contract_a(ew3: Web3):
    contract_a_code = Op.SSTORE(STORAGE_SLOT_2, 0x2) + Op.SSTORE(STORAGE_SLOT_1, 0x1)
    return deploy_contract_using_deploy_code(ew3, contract_a_code)

@pytest.fixture(scope="module")
def contract_b(ew3: Web3):
    contract_b_code = Op.SSTORE(STORAGE_SLOT_1, 0x2) + Op.SSTORE(STORAGE_SLOT_2, 0x1)
    return deploy_contract_using_deploy_code(ew3, contract_b_code)
    

# only test sample online
@pytest.mark.parametrize("tx_op_list", operation_permutations)
@pytest.mark.parametrize("epoch_structure", epoch_structures)
def test_multiple_authorizations_with_storage_changes(
    ew3: Web3,
    network,
    contract_a,
    contract_b,
    tx_op_list: list[StorageFuzzyOperation],
    epoch_structure: list[int]
):
    # Define storage slots we'll use for testing
    initial_storage = {
        STORAGE_SLOT_1: 0x0,
        STORAGE_SLOT_2: 0x0
    }
    expected_storage = initial_storage
    
    def apply_tx_op_to_storage(storage: dict[int, int], tx_op: StorageFuzzyOperation):
        if not tx_op.call_when_auth:
            return storage
        if tx_op.contract_selection == ContractSelection.RESET:
            return storage
        elif tx_op.contract_selection == ContractSelection.A:
            return tx_op.expected_storage
        elif tx_op.contract_selection == ContractSelection.B:
            return tx_op.expected_storage
        else:
            raise ValueError(f"Invalid contract selection: {tx_op.contract_selection}")
        
    def get_raw_tx(sender, sender_nonce: int, auth, auth_nonce: int, tx_op: StorageFuzzyOperation):
        auth_contract_address = "0x0000000000000000000000000000000000000000"
        if tx_op.contract_selection == ContractSelection.A:
            auth_contract_address = contract_a
        elif tx_op.contract_selection == ContractSelection.B:
            auth_contract_address = contract_b
        raw_tx = sign_eip7702_transaction_with_default_fields(
            ew3,
            sender=sender,
            transaction={
                "to": auth.address if tx_op.call_when_auth else ew3.eth.account.create().address,
                "authorizationList": [
                    sign_authorization(
                        contract_address=auth_contract_address,
                        nonce=auth_nonce,
                        chain_id=ew3.eth.chain_id,
                        private_key=auth.key.to_0x_hex(),
                    )
                ],
                "nonce": sender_nonce,
                "gas": 500_000
            }
        )
        return raw_tx
    
    # Create a auth account that will have its code changed
    auth = get_new_fund_account(ew3)
    sender = get_new_fund_account(ew3)
    auth_nonce = ew3.eth.get_transaction_count(auth.address)
    sender_nonce = ew3.eth.get_transaction_count(sender.address)
    
    copied_tx_op_list = tx_op_list.copy()
    
    # if is [1,1,2], it means 1 tx in 1 epoch, 1 tx in 1 epoch, then 2 tx in 1 epoch
    for tx_num in epoch_structure:
        raw_txs = []
        for _ in range(tx_num):
            tx_op = copied_tx_op_list.pop(0)
            expected_storage = apply_tx_op_to_storage(expected_storage, tx_op)
            raw_tx = get_raw_tx(sender, sender_nonce, auth, auth_nonce, tx_op)
            raw_txs.append(raw_tx)
            sender_nonce += 1
            auth_nonce += 1
        block_hash =network.client.generate_custom_block(network.client.best_block_hash(), [], raw_txs)
        current_block_hash = block_hash
        for _ in range(4):
            current_block_hash = network.client.generate_custom_block(current_block_hash, [], [])
        for slot, value in expected_storage.items():
            assert int(ew3.eth.get_storage_at(auth.address, slot).hex(), 16) == value
