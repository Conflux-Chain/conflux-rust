import pytest
from typing import Type, cast
from integration_tests.test_framework.util import load_contract_metadata
from web3 import Web3
from web3.contract import Contract
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
)


@pytest.fixture(scope="module")
def additional_secrets():
    return 1


@pytest.fixture(scope="module")
def erc20_factory(ew3: Web3) -> Type[Contract]:
    metadata = load_contract_metadata("MyToken")  # ERC20 contract
    contract_factory = ew3.eth.contract(
        bytecode=metadata["bytecode"],
        abi=metadata["abi"],
    )
    return contract_factory


@pytest.fixture(scope="module")
def contract_address(ew3: Web3, erc20_factory: Type[Contract], evm_accounts) -> str:
    tx_hash = erc20_factory.constructor(evm_accounts[0].address).transact()
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    return cast(str, receipt["contractAddress"])


# admin account is the last account in evm_accounts
# should not be used in trivial tests
@pytest.fixture(scope="module")
def admin_account(evm_accounts):
    return evm_accounts[-1]


def get_new_fund_account(ew3: Web3, admin_account):
    new_account = ew3.eth.account.create()
    tx_hash = ew3.eth.send_transaction(
        {
            "from": admin_account.address,
            "to": new_account.address,
            "value": ew3.to_wei(1, "ether"),
        }
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    return new_account


def assert_account_code_set_to_contract(
    ew3: Web3, account_address: str, contract_address: str
):
    code = ew3.eth.get_code(account_address)
    assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()


# use self as erc20 contract
# self nonce should increase by 2
def test_eip7702_sponsor_self(
    ew3: Web3, erc20_factory: Type[Contract], contract_address: str, admin_account
):

    sender = get_new_fund_account(ew3, admin_account)

    initial_nonce = ew3.eth.get_transaction_count(sender.address)
    chain_id = ew3.eth.chain_id

    authorization = sign_authorization(
        contract_address=contract_address,
        chain_id=chain_id,
        nonce=initial_nonce + 1,
        private_key=sender.key.to_0x_hex(),
    )

    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [authorization],
        },
    )
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)

    assert receipt["status"] == 1

    self_contract = erc20_factory(sender.address)

    assert_account_code_set_to_contract(ew3, sender.address, contract_address)

    assert self_contract.functions.balanceOf(sender.address).call() == 0

    assert ew3.eth.get_transaction_count(sender.address) == initial_nonce + 2


# test set code for a new account which is not in state
def test_eip7702_sponsor_new_account(
    ew3: Web3, erc20_factory: Type[Contract], contract_address: str, admin_account
):

    sender = get_new_fund_account(ew3, admin_account)

    signer = ew3.eth.account.create()

    authorization = sign_authorization(
        contract_address=contract_address,
        chain_id=ew3.eth.chain_id,
        nonce=0,
        private_key=signer.key.to_0x_hex(),
    )

    sender_nonce = ew3.eth.get_transaction_count(sender.address)
    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [authorization],
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    # verify code is set
    code = ew3.eth.get_code(signer.address)
    assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()
    # verify nonce is increased
    assert ew3.eth.get_transaction_count(sender.address) == sender_nonce + 1
    assert ew3.eth.get_transaction_count(signer.address) == 1


# Corresponds to ethereum-spec-tests::test_tx_into_self_delegating_set_code
def test_tx_into_self_delegating_set_code(ew3: Web3, admin_account):
    auth_signer = get_new_fund_account(ew3, admin_account)

    ew3.eth.wait_for_transaction_receipt(
        send_eip7702_transaction(
            ew3,
            get_new_fund_account(ew3, admin_account),
            {
                "authorizationList": [
                    sign_authorization(
                        contract_address=auth_signer.address,
                        chain_id=ew3.eth.chain_id,
                        nonce=ew3.eth.get_transaction_count(auth_signer.address),
                        private_key=auth_signer.key.to_0x_hex(),
                    )
                ]
            },
        )
    )

    # Verify the code is set to self-delegate
    assert_account_code_set_to_contract(ew3, auth_signer.address, auth_signer.address)
    # Verify nonce is increased
    assert ew3.eth.get_transaction_count(auth_signer.address) == 1

# Corresponds to ethereum-spec-tests::test_tx_into_chain_delegating_set_code
def test_tx_into_chain_delegating_set_code(ew3: Web3, admin_account):
    auth_signer_1 = get_new_fund_account(ew3, admin_account)
    auth_signer_2 = get_new_fund_account(ew3, admin_account)

    ew3.eth.wait_for_transaction_receipt(
        send_eip7702_transaction(
            ew3,
            get_new_fund_account(ew3, admin_account),
            {
                "authorizationList": [
                    sign_authorization(
                        contract_address=auth_signer_1.address,
                        chain_id=ew3.eth.chain_id,
                        nonce=0,
                        private_key=auth_signer_2.key.to_0x_hex(),
                    ),
                    sign_authorization(
                        contract_address=auth_signer_2.address,
                        chain_id=ew3.eth.chain_id,
                        nonce=0,
                        private_key=auth_signer_1.key.to_0x_hex(),
                    ),
                ]
            },
        )
    )

    # Verify the code is set to self-delegate
    assert_account_code_set_to_contract(ew3, auth_signer_1.address, auth_signer_2.address)
    assert_account_code_set_to_contract(ew3, auth_signer_2.address, auth_signer_1.address)
    # Verify nonce is increased
    assert ew3.eth.get_transaction_count(auth_signer_1.address) == 1
    assert ew3.eth.get_transaction_count(auth_signer_2.address) == 1