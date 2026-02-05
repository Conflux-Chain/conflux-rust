import json
from web3.tracing import Tracing
from web3 import Web3
from typing import List
from web3.types import FilterTrace, TxReceipt
from integration_tests.test_framework.util import load_contract_metadata
from integration_tests.test_framework.util.eip7702.eip7702 import (
    send_eip7702_transaction,
    sign_authorization,
)


def verify_erc20_token_transfer_trace(traces: List[FilterTrace], receipt: TxReceipt):
    assert len(traces) == 1

    trace0 = traces[0]
    assert trace0["type"] == "call"
    assert trace0["transactionHash"] == receipt["transactionHash"]
    assert trace0["blockHash"] == receipt["blockHash"]
    assert trace0["blockNumber"] == receipt["blockNumber"]
    assert trace0["transactionPosition"] == 0
    assert trace0["valid"] == True
    assert trace0["result"] != None

    action = trace0["action"]
    assert action["from"] == receipt["from"]
    assert action["to"] == receipt["to"]
    assert action["callType"] == "call"


def test_trace_filter(ew3_tracing, erc20_token_transfer):
    receipt = erc20_token_transfer["receipt"]
    traces = ew3_tracing.trace_filter(
        {"fromBlock": Web3.to_hex(receipt["blockNumber"])}
    )
    verify_erc20_token_transfer_trace(traces, receipt)


def test_trace_block(ew3_tracing, erc20_token_transfer):
    receipt = erc20_token_transfer["receipt"]
    traces = ew3_tracing.trace_block(receipt["blockNumber"])
    verify_erc20_token_transfer_trace(traces, receipt)


def test_trace_transaction(ew3_tracing, erc20_token_transfer):
    receipt = erc20_token_transfer["receipt"]
    tx_hash = erc20_token_transfer["tx_hash"]

    traces = ew3_tracing.trace_transaction(tx_hash)
    verify_erc20_token_transfer_trace(traces, receipt)

def test_trace_suicide(ew3, evm_accounts, ew3_tracing):
    destroyable_contract_meta = load_contract_metadata("ContractCanBeDestroyed")
    # destroy_tester_meta = load_contract_metadata("SelfDestructTester")
    account = evm_accounts[0]

    # deploy contract
    Contract = ew3.eth.contract(
        abi=destroyable_contract_meta["abi"], bytecode=destroyable_contract_meta["bytecode"]
    )
    tx_hash = Contract.constructor().transact()
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    deploy_receipt = ew3.eth.get_transaction_receipt(tx_hash)
    assert deploy_receipt["status"] == 1
    contract_address = deploy_receipt["contractAddress"]

    # transfer 1 ether to the new deployed contract
    tx_hash = ew3.eth.send_transaction({
        "from": account.address,
        "value": ew3.to_wei(1, 'ether'),
        "to": contract_address
    })
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    contract = ew3.eth.contract(address=contract_address, abi=destroyable_contract_meta["abi"])

    tx_hash = contract.functions.destroy(account.address).transact()
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    traces = ew3_tracing.trace_transaction(tx_hash)
    assert len(traces) == 2
    assert traces[1]["type"] == "suicide"
    assert traces[1]["action"]["refundAddress"] == account.address
    assert traces[1]["traceAddress"] == [0]


def _fund_account(ew3: Web3, from_address: str, to_address: str, amount_wei: int) -> None:
    tx_hash = ew3.eth.send_transaction(
        {"from": from_address, "to": to_address, "value": amount_wei}
    )
    ew3.eth.wait_for_transaction_receipt(tx_hash)


def test_trace_block_set_auth(ew3: Web3, evm_accounts, erc20_contract) -> None:
    sender = ew3.eth.account.create()
    auth = ew3.eth.account.create()

    _fund_account(ew3, evm_accounts[0].address, sender.address, ew3.to_wei(1, "ether"))
    _fund_account(ew3, evm_accounts[0].address, auth.address, ew3.to_wei(1, "ether"))

    chain_id = ew3.eth.chain_id
    contract_address = erc20_contract["contract"].address
    authorization = sign_authorization(
        contract_address=contract_address,
        chain_id=chain_id,
        nonce=0,
        private_key=auth.key.to_0x_hex(),
    )

    tx_hash = send_eip7702_transaction(
        ew3,
        sender=sender,
        transaction={
            "authorizationList": [authorization],
            "to": contract_address,
            "value": 0,
            "gas": 200000,
        },
    )
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)

    traces = ew3.manager.request_blocking(
        "trace_blockSetAuth", [Web3.to_hex(receipt["blockNumber"])]
    )

    assert traces is not None
    assert len(traces) >= 1

    trace0 = traces[0]
    assert trace0["transactionHash"] == receipt["transactionHash"].to_0x_hex()
    assert trace0["blockHash"] == receipt["blockHash"].to_0x_hex()
    assert trace0["blockNumber"] == receipt["blockNumber"]
    assert trace0["transactionPosition"] == receipt["transactionIndex"]
    assert trace0["result"] == "success"

    action = trace0["action"]
    assert action["address"].lower() == contract_address.lower()
    assert action["chainId"] == Web3.to_hex(chain_id)
    assert action["nonce"] == "0x0"
