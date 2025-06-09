import json
from web3.tracing import Tracing
from web3 import Web3
from typing import List
from web3.types import FilterTrace, TxReceipt
from integration_tests.test_framework.util import load_contract_metadata


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

    tx_hash = contract.destroy(account.address).transact()
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    traces = ew3_tracing.trace_transaction(tx_hash)
    assert len(traces) == 1