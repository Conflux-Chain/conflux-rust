import pytest
from typing import Type, cast
from integration_tests.test_framework.util import load_contract_metadata
from web3 import Web3
from web3.contract import Contract
from web3.middleware.signing import SignAndSendRawMiddlewareBuilder
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
)
from ethereum_test_tools import (
    Initcode,
    Conditional,
    Opcodes as Op,
    Storage,
    Bytecode,
    Macros as Om
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
            "to": "0x0000000000000000000000000000000000000000",  # set to a random address
        },
    )
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)

    assert receipt["status"] == 1

    self_contract = erc20_factory(sender.address)

    assert_account_code_set_to_contract(ew3, sender.address, contract_address)

    assert self_contract.functions.balanceOf(sender.address).call() == 0

    assert ew3.eth.get_transaction_count(sender.address) == initial_nonce + 2
    
    ew3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(sender.key))
    # sender send random tx
    tx_hash = ew3.eth.send_transaction(
        {
            "from": sender.address,
            "to": "0x0000000000000000000000000000000000000000",
            "value": ew3.to_wei(0.5, "ether"),
        }
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash, timeout=1, poll_latency=0.5)
    
    # verify nonce is increased
    assert ew3.eth.get_transaction_count(sender.address) == initial_nonce + 3
    


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
            "to": "0x0000000000000000000000000000000000000000",  # set to a random address
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    # verify code is set
    code = ew3.eth.get_code(signer.address)
    assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()
    # verify nonce is increased
    assert ew3.eth.get_transaction_count(sender.address) == sender_nonce + 1
    assert ew3.eth.get_transaction_count(signer.address) == 1


# test set code for a new account which is not in state
def test_eip7702_many_delegations(
    ew3: Web3, admin_account
):
    signer_count = 38
    contract_addresses = [f"0x{(i+1):040x}" for i in range(signer_count)]
    success_slot = 1
    entry_code = Op.SSTORE(success_slot, 1) + Op.STOP
    entry_address = deploy_contract_using_deploy_code(ew3, entry_code)

    sender = get_new_fund_account(ew3, admin_account)

    signers = [ew3.eth.account.create() for _ in range(signer_count)]


    sender_nonce = ew3.eth.get_transaction_count(sender.address)
    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [sign_authorization(
                contract_address=contract_addresses[i],
                chain_id=ew3.eth.chain_id,
                nonce=0,
                private_key=signer.key.to_0x_hex(),
            ) for (i, signer) in enumerate(signers)],
            "to": entry_address,
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    
    storage_value = ew3.eth.get_storage_at(entry_address, success_slot)
    assert int(storage_value.hex(), 16) == 1

    # verify code is set
    for (i, signer) in enumerate(signers):
        code = ew3.eth.get_code(signer.address)
        assert code.to_0x_hex() == "0xef0100" + contract_addresses[i][2:].lower()
        # verify nonce is increased
        assert ew3.eth.get_transaction_count(sender.address) == sender_nonce + 1
        assert ew3.eth.get_transaction_count(signer.address) == 1

    


@pytest.mark.parametrize(
    "no_code_before_reset",
    [
        pytest.param(True, id="no-code-before-reset"),
        pytest.param(False, id="has-code-before-reset"),
    ],
)
@pytest.mark.parametrize(
    "sponsor_self_when_reset",
    [
        pytest.param(True, id="sponsor-self"),
        pytest.param(False, id="not-sponsor-self"),
    ],
)
def test_reset_eip7702_sponsor_self(
    ew3: Web3, erc20_factory: Type[Contract], contract_address: str, admin_account, no_code_before_reset, sponsor_self_when_reset
):

    sender = get_new_fund_account(ew3, admin_account)
    if not no_code_before_reset:
        authorization = sign_authorization(
            contract_address=contract_address,
            chain_id=ew3.eth.chain_id,
            nonce=ew3.eth.get_transaction_count(sender.address)+1,
            private_key=sender.key.to_0x_hex(),
        )

        tx_hash = send_eip7702_transaction(
            ew3,
            sender,
            {
                "authorizationList": [authorization],
                "to": ew3.eth.account.create().address,  # set to a random address
            },
        )
        ew3.eth.wait_for_transaction_receipt(tx_hash)

        # verify code is set
        code = ew3.eth.get_code(sender.address)
        assert code.to_0x_hex() == "0xef0100" + contract_address[2:].lower()
    
    # reset the code
    tx_hash = send_eip7702_transaction(
        ew3,
        sender if sponsor_self_when_reset else get_new_fund_account(ew3, admin_account),
        {
            "authorizationList": [
                sign_authorization(
                    contract_address="0x0000000000000000000000000000000000000000",
                    chain_id=ew3.eth.chain_id,
                    nonce=ew3.eth.get_transaction_count(sender.address)+ (1 if sponsor_self_when_reset else 0),
                    private_key=sender.key.to_0x_hex(),
                )
            ],
            # "to": sender.address,  # send to self
            "to": ew3.eth.account.create().address,  # send to self
            "gas": 1000000,
        },
    )
    # 
    ew3.eth.wait_for_transaction_receipt(tx_hash, timeout=2, poll_latency=0.5)

    # verify code is reset
    code = ew3.eth.get_code(sender.address)
    assert code.to_0x_hex() == "0x"

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
                ],
                "to": "0x0000000000000000000000000000000000000000",  # set to a random address
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
                ],
                "to": "0x0000000000000000000000000000000000000000",  # set to a random address
            },
        )
    )

    # Verify the code is set to self-delegate
    assert_account_code_set_to_contract(ew3, auth_signer_1.address, auth_signer_2.address)
    assert_account_code_set_to_contract(ew3, auth_signer_2.address, auth_signer_1.address)
    # Verify nonce is increased
    assert ew3.eth.get_transaction_count(auth_signer_1.address) == 1
    assert ew3.eth.get_transaction_count(auth_signer_2.address) == 1

# corresponds to ethereum-spec-tests::test_set_code_to_sstore
@pytest.mark.parametrize(
    "tx_value",
    [0, 1],
)
@pytest.mark.parametrize(
    "suffix,succeeds",
    [
        pytest.param(Op.STOP, True, id="stop"),
        pytest.param(Op.RETURN(0, 0), True, id="return"),
        pytest.param(Op.REVERT(0, 0), False, id="revert"),
        pytest.param(Op.INVALID, False, id="invalid"),
        pytest.param(Om.OOG + Op.STOP, False, id="out-of-gas"),
    ],
)
def test_set_code_to_sstore(
    ew3: Web3, 
    admin_account, 
    tx_value,
    suffix,
    succeeds
):
    storage = Storage()
    sender = get_new_fund_account(ew3, admin_account)
    
    set_code = (
        Op.SSTORE(storage.store_next(sender.address), Op.ORIGIN)
        + Op.SSTORE(storage.store_next(sender.address), Op.CALLER)
        + Op.SSTORE(storage.store_next(tx_value), Op.CALLVALUE)
        + suffix
    )
    
    contract_address = deploy_contract_using_deploy_code(ew3, set_code)
    
    tx_hash = send_eip7702_transaction(
        ew3,
        sender=sender,
        # send contract to self to execute the code
        transaction={
            "authorizationList": [
                sign_authorization(contract_address=contract_address, chain_id=ew3.eth.chain_id, nonce=1, private_key=sender.key.to_0x_hex())
            ],
            "to": sender.address,
            "value": tx_value,
            "gas": 200000,
        }
    )
    
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    
    for key in storage:
        assert int(ew3.eth.get_storage_at(contract_address, key).hex(), 16) == 0  # type: ignore
    
    if succeeds:
        assert receipt["status"] == 1
        for key in storage:
            assert int(ew3.eth.get_storage_at(sender.address, key).hex(), 16) == storage[key]  # type: ignore
    else:
        assert receipt["status"] == 0
    
    assert ew3.eth.get_transaction_count(sender.address) == 2
