import json
from web3.tracing import Tracing
from web3 import Web3
from typing import List
from web3.types import FilterTrace, TxReceipt


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
