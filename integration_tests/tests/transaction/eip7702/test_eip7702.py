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
    Opcodes as Op,
    Storage,
    Bytecode,
    Macros as Om,
)
from web3.types import RPCEndpoint


@pytest.fixture(scope="module")
def erc20_factory(ew3: Web3) -> Type[Contract]:
    metadata = load_contract_metadata("MyToken")  # ERC20 contract
    contract_factory = ew3.eth.contract(
        bytecode=metadata["bytecode"],
        abi=metadata["abi"],
    )
    return contract_factory

# The commented code is for testing if conflux's implementation 
# is compatible with anvil's implementation
# @pytest.fixture(scope="module", params=["anvil", "conflux"])
# def web3_setting_pair(network, request):
#     if request.param == "anvil":
#         from eth_account import Account as EthAccount
#         EthAccount.enable_unaudited_hdwallet_features()
#         w3 = Web3(
#             Web3.HTTPProvider("http://localhost:8545")
#         )
#         acct = EthAccount.from_mnemonic(
#             "test test test test test test test test test test test junk",
#             account_path="m/44'/60'/0'/0/0",
#         )
#         w3.eth.default_account = acct.address
#         w3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(acct.key))
#         return w3, acct
#     else:
#         network.ew3.eth.default_account = network.evm_accounts[-1].address
#         return network.ew3, network.evm_accounts[-1]


# @pytest.fixture(scope="module")
# def ew3(web3_setting_pair):
#     return web3_setting_pair[0]


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

# use self as erc20 contract
# self nonce should increase by 2
def test_eip7702_sponsor_self(
    ew3: Web3, erc20_factory: Type[Contract], contract_address: str
):

    sender = get_new_fund_account(ew3)

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
    ew3: Web3, erc20_factory: Type[Contract], contract_address: str
):

    sender = get_new_fund_account(ew3)

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
def test_eip7702_many_delegations(ew3: Web3):
    signer_count = 38
    contract_addresses = [f"0x{(i+1):040x}" for i in range(signer_count)]
    success_slot = 1
    entry_code = Op.SSTORE(success_slot, 1) + Op.STOP
    entry_address = deploy_contract_using_deploy_code(ew3, entry_code)

    sender = get_new_fund_account(ew3)

    signers = [ew3.eth.account.create() for _ in range(signer_count)]

    sender_nonce = ew3.eth.get_transaction_count(sender.address)
    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [
                sign_authorization(
                    contract_address=contract_addresses[i],
                    chain_id=ew3.eth.chain_id,
                    nonce=0,
                    private_key=signer.key.to_0x_hex(),
                )
                for (i, signer) in enumerate(signers)
            ],
            "to": entry_address,
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    storage_value = ew3.eth.get_storage_at(entry_address, success_slot)  # type: ignore
    assert int(storage_value.hex(), 16) == 1

    # verify code is set
    for i, signer in enumerate(signers):
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
    ew3: Web3,
    erc20_factory: Type[Contract],
    contract_address: str,
    no_code_before_reset,
    sponsor_self_when_reset,
):

    sender = get_new_fund_account(ew3)
    if not no_code_before_reset:
        authorization = sign_authorization(
            contract_address=contract_address,
            chain_id=ew3.eth.chain_id,
            nonce=ew3.eth.get_transaction_count(sender.address) + 1,
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
        sender if sponsor_self_when_reset else get_new_fund_account(ew3),
        {
            "authorizationList": [
                sign_authorization(
                    contract_address="0x0000000000000000000000000000000000000000",
                    chain_id=ew3.eth.chain_id,
                    nonce=ew3.eth.get_transaction_count(sender.address)
                    + (1 if sponsor_self_when_reset else 0),
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

# current implementation shows conflux's implementation is compatible
# with anvil's implementation
# TODO: check geth's implementation
def test_eip7702_trace_rpc(ew3: Web3):
    contract_c_code = Op.STOP

    contract_c_address = deploy_contract_using_deploy_code(ew3, contract_c_code)

    contract_b_code = Op.CALL(Op.GAS, contract_c_address, 0x0, 0x0, 0x0, 0x0, 0x0)
    contract_b_address = deploy_contract_using_deploy_code(ew3, contract_b_code)

    auth = get_new_fund_account(ew3)
    sender = get_new_fund_account(ew3)

    tx_hash = send_eip7702_transaction(
        ew3,
        sender=sender,
        transaction={
            "authorizationList": [
                sign_authorization(
                    contract_address=contract_b_address,
                    chain_id=ew3.eth.chain_id,
                    nonce=0,
                    private_key=auth.key.to_0x_hex(),
                )
            ],
            "to": contract_b_address,
            "value": 0,
            "gas": 100000,
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    assert_account_code_set_to_contract(ew3, auth.address, contract_b_address)

    call_trace = ew3.manager.request_blocking(
        RPCEndpoint("debug_traceTransaction"), [tx_hash, {"tracer": "callTracer"}]
    )
    print("Call trace:", call_trace)
    # Verify trace structure: should be sender -> B -> C, not sender -> auth -> B -> C
    # 1. Check if top-level call's from address is sender's address
    assert (
        call_trace["from"].lower() == sender.address.lower()
    ), "Trace should show call originated from sender address"

    # 2. Check if inner call's from/to addresses are correct
    # If EIP-7702 behaves correctly, trace should show B calling C
    assert "calls" in call_trace and call_trace["calls"]
    inner_call = call_trace["calls"][0]
    assert inner_call["from"].lower() == contract_b_address.lower()
    assert inner_call["to"].lower() == contract_c_address.lower()


def test_eip7702_nonce_skip(ew3: Web3):
    sender = get_new_fund_account(ew3)
    auth = get_new_fund_account(ew3)

    # invalid nonce
    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [
                sign_authorization(
                    contract_address=ew3.eth.account.create().address,
                    chain_id=ew3.eth.chain_id,
                    nonce=1,
                    private_key=auth.key.to_0x_hex(),
                )
            ],
            "to": ew3.eth.account.create().address,
            "value": 0,
            "gas": 100000,
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    
    assert ew3.eth.get_transaction_count(auth.address) == 0, "authorization should not take effect"
    assert ew3.eth.get_code(auth.address).to_0x_hex() == "0x", "code should not be set"

def test_eip7702_nonce_duplicate(ew3: Web3):
    sender = get_new_fund_account(ew3)
    auth = get_new_fund_account(ew3)
    
    random_acct_list = [ew3.eth.account.create() for _ in range(10)]

    # invalid nonce
    tx_hash = send_eip7702_transaction(
        ew3,
        sender,
        {
            "authorizationList": [
                sign_authorization(
                    contract_address=random_acct_list[0].address,
                    chain_id=ew3.eth.chain_id,
                    nonce=0,
                    private_key=auth.key.to_0x_hex(),
                ),
                sign_authorization(
                    contract_address=random_acct_list[1].address,
                    chain_id=ew3.eth.chain_id,
                    nonce=0,
                    private_key=auth.key.to_0x_hex(),
                )
            ],
            "to": ew3.eth.account.create().address,
            "value": 0,
            "gas": 100000,
        },
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    
    assert ew3.eth.get_transaction_count(auth.address) == 1
    assert_account_code_set_to_contract(ew3, auth.address, random_acct_list[0].address)
