import json
from typing import List, Type
from hexbytes import HexBytes
import pytest
from conflux_web3 import Web3 as CWeb3
from web3.types import FilterTrace

from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import load_contract_metadata
from integration_tests.test_framework.util.common import (
    reserialize_json,
    NULL_ADDRESS,
    encode_u256,
    number_to_topic,
)


@pytest.fixture(scope="module")
def conflux_side_contract(network: ConfluxTestFramework):
    return network.deploy_contract("CrossSpaceTraceTestConfluxSide")


@pytest.fixture(scope="module")
def evm_side_contract(network: ConfluxTestFramework):
    return network.deploy_evm_contract("CrossSpaceTraceTestEVMSide")


def test_callEvmEmpty(cw3: CWeb3, ew3, ew3_tracing, conflux_side_contract, evm_side_contract):
    tx_hash = conflux_side_contract.functions.callEVMEmpty(evm_side_contract.address).transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]

    trace0 = ew3_tracing.trace_transaction(txs[0]["hash"])
    assert len(trace0) == 1

    trace1 = ew3_tracing.trace_transaction(txs[1]["hash"])
    assert len(trace1) == 1


def test_callEVM(cw3: CWeb3, ew3, ew3_tracing, conflux_side_contract, evm_side_contract):
    tx_hash = conflux_side_contract.functions.callEVM(evm_side_contract.address, 1).transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)

    assert receipt["outcomeStatus"] == 0

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 2

    phantom0 = txs[0]
    assert phantom0["from"] == NULL_ADDRESS
    assert phantom0.to == conflux_side_contract.address.mapped_evm_space_address
    assert phantom0.input.to_0x_hex() == tx_hash.to_0x_hex() + encode_u256(0)
    assert phantom0.gas == 0
    assert phantom0.gasPrice == 0
    assert phantom0.nonce == 0
    assert phantom0.status == "0x1"
    assert phantom0.blockHash == block.hash
    assert phantom0.blockNumber == block.number
    assert phantom0.transactionIndex == 0

    trace0 = ew3_tracing.trace_transaction(phantom0["hash"])
    expect: List[FilterTrace] = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0.to,
                "input": phantom0.input.to_0x_hex(),
                "gas": 0,
                "value": phantom0.value,
            },
            "result": {
                "gasUsed": 0,
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0.blockHash,
            "blockNumber": phantom0.blockNumber,
            "transactionHash": phantom0.hash,
            "transactionPosition": phantom0.transactionIndex,
            "valid": True,
        }
    ]
    assert reserialize_json(ew3.to_json(trace0)) == reserialize_json(ew3.to_json(expect))

    phantom1 = txs[1]

    assert phantom1["from"] == conflux_side_contract.address.mapped_evm_space_address
    assert phantom1.to == evm_side_contract.address
    assert phantom1.input.to_0x_hex() == evm_side_contract.encode_abi(
        abi_element_identifier="call", args=[1]
    )  # self.evmContract.encode_abi(abi_element_identifier="call", args=[1]))
    assert phantom1.status == "0x1"
    assert phantom1.blockHash == block["hash"]
    assert phantom1.blockNumber == block["number"]
    assert phantom1.transactionIndex == 1

    trace1 = ew3_tracing.trace_transaction(phantom1["hash"])

    # trace1 = self.nodes[0].ethrpc.trace_transaction(phantom1["hash"])

    expect_trace1: List[FilterTrace] = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom1["from"],
                "to": phantom1["to"],
                "input": phantom1["input"],
                "gas": 0,
                "value": phantom1["value"],
            },
            "result": {
                "gasUsed": 0,
                "output": number_to_topic(1),
            },
            "subtraces": 1,
            "traceAddress": [],
            "blockHash": phantom1["blockHash"],
            "blockNumber": phantom1["blockNumber"],
            "transactionHash": phantom1["hash"],
            "transactionPosition": phantom1["transactionIndex"],
            "valid": True,
        },
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": evm_side_contract.address,
                "to": evm_side_contract.address,
                "input": evm_side_contract.encode_abi(abi_element_identifier="call", args=[0]),
                "gas": 0,
                "value": 0,
            },
            "result": {
                "gasUsed": 0,
                "output": number_to_topic(0),
            },
            "subtraces": 0,
            "traceAddress": [0],
            "blockHash": block["hash"],
            "blockNumber": block["number"],
            "transactionHash": phantom1["hash"],
            "transactionPosition": phantom1["transactionIndex"],
            "valid": True,
        },
    ]

    assert reserialize_json(ew3.to_json(trace1)) == reserialize_json(ew3.to_json(expect_trace1))

    # test trace_block
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert block_traces == trace0 + trace1

    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert block_traces == trace0 + trace1

    filtered = ew3_tracing.trace_filter({"fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"]})
    assert reserialize_json(ew3.to_json(filtered)) == reserialize_json(ew3.to_json(block_traces))

    filtered = ew3_tracing.trace_filter(
        {
            "fromBlock": receipt["epochNumber"],
            "fromAddress": [
                conflux_side_contract.address.mapped_evm_space_address,
                evm_side_contract.address,
                NULL_ADDRESS,
            ],
            "toAddress": [
                conflux_side_contract.address.mapped_evm_space_address,
                evm_side_contract.address,
            ],
        }
    )
    assert filtered == block_traces


def test_staticCallEVM(cw3: CWeb3, ew3, ew3_tracing, conflux_side_contract, evm_side_contract):
    tx_hash = conflux_side_contract.functions.staticCallEVM(evm_side_contract.address, 1).transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)

    assert receipt["outcomeStatus"] == 0

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 0

    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert block_traces == []

    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert block_traces == []


def test_createEVM(
    cw3: CWeb3,
    ew3,
    ew3_tracing,
    conflux_side_contract,
    internal_contracts,
):
    evm_side_metadata = load_contract_metadata("CrossSpaceTraceTestEVMSide")

    tx_hash = conflux_side_contract.functions.createEVM(evm_side_metadata["bytecode"]).transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)

    assert receipt["outcomeStatus"] == 0

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 2

    phantom0 = txs[0]
    assert phantom0["from"] == NULL_ADDRESS
    assert phantom0["to"] == conflux_side_contract.address.mapped_evm_space_address
    assert phantom0["input"].to_0x_hex() == tx_hash.to_0x_hex() + encode_u256(0)
    assert phantom0.gas == 0
    assert phantom0.gasPrice == 0
    assert phantom0.nonce == 0
    assert phantom0.status == "0x1"
    assert phantom0.blockHash == block["hash"]
    assert phantom0.blockNumber == block["number"]
    assert phantom0.transactionIndex == 0

    trace0 = ew3_tracing.trace_transaction(phantom0["hash"])
    assert len(trace0) == 1

    expect_trace0: List[FilterTrace] = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"].to_0x_hex(),
                "gas": 0,
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": 0,
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": phantom0["blockNumber"],
            "transactionHash": phantom0["hash"],
            "transactionPosition": phantom0["transactionIndex"],
            "valid": True,
        }
    ]

    assert reserialize_json(ew3.to_json(trace0)) == reserialize_json(ew3.to_json(expect_trace0))

    phantom1 = txs[1]
    assert phantom1["from"] == conflux_side_contract.address.mapped_evm_space_address
    assert phantom1["to"] == None
    assert phantom1["input"].to_0x_hex() == evm_side_metadata["bytecode"]
    assert phantom1["status"] == "0x1"
    assert phantom1["blockHash"] == block["hash"]
    assert phantom1["blockNumber"] == block["number"]
    assert phantom1["transactionIndex"] == 1

    trace1 = ew3_tracing.trace_transaction(phantom1["hash"])
    assert len(trace1) == 1

    cross_space_call = internal_contracts["CrossSpaceCall"]
    event_datas = cross_space_call.events.Create().process_receipt(receipt)
    new_contract_addr: str = event_datas[0]["args"]["contract_address"]

    expect_trace1: List[FilterTrace] = [
        {
            "type": "create",
            "action": {
                "createType": "create",
                "from": phantom1["from"],
                "init": phantom1["input"].to_0x_hex(),
                "gas": 0,
                "value": phantom1["value"],
            },
            "result": {
                "address": ew3.to_checksum_address(new_contract_addr),
                "gasUsed": 0,
                # Skip first 34 bytes ("0x" + 64 hex chars) to get runtime bytecode
                "code": "0x" + evm_side_metadata["bytecode"][66:],
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom1["blockHash"],
            "blockNumber": phantom1["blockNumber"],
            "transactionHash": phantom1["hash"],
            "transactionPosition": phantom1["transactionIndex"],
            "valid": True,
        }
    ]

    assert reserialize_json(ew3.to_json(trace1)) == reserialize_json(ew3.to_json(expect_trace1))

    # test trace_block
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert block_traces == trace0 + trace1

    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert block_traces == trace0 + trace1

    # test trace_filter
    filtered = ew3_tracing.trace_filter({"fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"]})
    assert filtered == block_traces


def test_transferEVM(cw3: CWeb3, ew3, ew3_tracing, evm_accounts, conflux_side_contract, evm_side_contract):
    evm_account = evm_accounts[0]
    tx_hash = conflux_side_contract.functions.transferEVM(evm_account.address).transact({"value": 0x222})
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)

    assert receipt["outcomeStatus"] == 0

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 4  # 2 internal contract calls, 2 phantom txs each

    # phantom #0: balance transfer to mapped account
    phantom0 = txs[0]
    assert phantom0["from"] == NULL_ADDRESS
    assert phantom0["to"] == conflux_side_contract.address.mapped_evm_space_address
    assert phantom0["input"].to_0x_hex() == tx_hash.to_0x_hex() + encode_u256(0)
    assert phantom0["gas"] == 0
    assert phantom0["gasPrice"] == 0
    assert phantom0["value"] == 273
    assert phantom0["nonce"] == 0
    assert phantom0["status"] == "0x1"
    assert phantom0["blockHash"] == block["hash"]
    assert phantom0["blockNumber"] == block["number"]
    assert phantom0["transactionIndex"] == 0

    trace0 = ew3_tracing.trace_transaction(txs[0]["hash"])
    expect_trace0: List[FilterTrace] = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"],
                "gas": 0,
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": 0,
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": phantom0["blockNumber"],
            "transactionHash": phantom0["hash"],
            "transactionPosition": phantom0["transactionIndex"],
            "valid": True,
        }
    ]
    assert reserialize_json(ew3.to_json(trace0)) == reserialize_json(ew3.to_json(expect_trace0))

    # phantom #1: contract call from mapped account
    phantom1 = txs[1]
    assert phantom1["from"] == conflux_side_contract.address.mapped_evm_space_address
    assert phantom1["to"] == evm_account.address
    assert phantom1["input"].to_0x_hex() == "0x"
    assert phantom1["value"] == 273
    assert phantom1["status"] == "0x1"
    assert phantom1["blockHash"] == block["hash"]
    assert phantom1["blockNumber"] == block["number"]
    assert phantom1["transactionIndex"] == 1

    trace1 = ew3_tracing.trace_transaction(phantom1["hash"])

    expect_trace1: List[FilterTrace] = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom1["from"],
                "to": phantom1["to"],
                "input": phantom1["input"],
                "gas": 0,
                "value": phantom1["value"],
            },
            "result": {
                "gasUsed": 0,
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom1["blockHash"],
            "blockNumber": phantom1["blockNumber"],
            "transactionHash": phantom1["hash"],
            "transactionPosition": phantom1["transactionIndex"],
            "valid": True,
        }
    ]

    assert reserialize_json(ew3.to_json(trace1)) == reserialize_json(ew3.to_json(expect_trace1))

    # phantom #2: balance transfer to mapped account
    # this is the same as phantom #0, but `input` should use index 1 instead of 0
    phantom2 = txs[2]
    assert phantom2["input"].to_0x_hex() == tx_hash.to_0x_hex() + encode_u256(1)
    trace2 = ew3_tracing.trace_transaction(phantom2["hash"])
    expect_trace2 = expect_trace0.copy()
    expect_trace2[0]["transactionHash"] = phantom2["hash"]
    expect_trace2[0]["action"]["input"] = tx_hash.to_0x_hex() + encode_u256(1)
    expect_trace2[0]["transactionPosition"] = 2

    assert reserialize_json(ew3.to_json(trace2)) == reserialize_json(ew3.to_json(expect_trace2))

    # test trace_block
    trace3 = ew3_tracing.trace_transaction(txs[3]["hash"])
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert block_traces == trace0 + trace1 + trace2 + trace3
    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert block_traces == trace0 + trace1 + trace2 + trace3
    # test trace_filter
    filtered = ew3_tracing.trace_filter({"fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"]})
    assert filtered == block_traces


def test_withdrawFromMapped_fail_if_insufficient_funds(
    cw3: CWeb3, ew3, evm_accounts, ew3_tracing, conflux_side_contract, evm_side_contract
):
    evm_account = evm_accounts[0]
    tx_hash = conflux_side_contract.functions.withdrawFromMapped(0x222).transact({"gas": 1000000, "storageLimit": 1000})
    try:
        cw3.cfx.wait_for_transaction_receipt(tx_hash)
    except:
        pass

    receipt = cw3.cfx.get_transaction_receipt(tx_hash)

    assert receipt["outcomeStatus"] == 1


def test_withdrawFromMapped(cw3: CWeb3, ew3, evm_accounts, ew3_tracing, conflux_side_contract, evm_side_contract):
    evm_account = evm_accounts[0]
    tx_hash = ew3.eth.send_transaction(
        {
            "from": evm_account.address,
            "to": conflux_side_contract.address.mapped_evm_space_address,
            "value": 0x123,
        }
    )

    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1

    tx_hash = conflux_side_contract.functions.withdrawFromMapped(0x123).transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 0

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 1

    # phantom #0: balance transfer from mapped account
    phantom0 = txs[0]
    assert phantom0["from"] == conflux_side_contract.address.mapped_evm_space_address
    assert phantom0["to"] == NULL_ADDRESS
    assert phantom0["input"].to_0x_hex() == "0x"
    assert phantom0["gas"] == 0
    assert phantom0["gasPrice"] == 0
    assert phantom0["value"] == 0x123
    assert phantom0["status"] == "0x1"
    assert phantom0["blockHash"] == block["hash"]
    assert phantom0["blockNumber"] == block["number"]
    assert phantom0["transactionIndex"] == 0

    # NOTE: nonce is >0 because callEVM and tranferToEVM used the mapped addr
    trace0 = ew3_tracing.trace_transaction(phantom0["hash"])
    expect_trace0: List[FilterTrace] = [
        {
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"].to_0x_hex(),
                "gas": 0,
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": 0,
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": phantom0["blockNumber"],
            "transactionHash": phantom0["hash"],
            "transactionPosition": phantom0["transactionIndex"],
            "valid": True,
        }
    ]

    assert reserialize_json(ew3.to_json(trace0)) == reserialize_json(ew3.to_json(expect_trace0))

    # test trace_block
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert block_traces == trace0
    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert block_traces == trace0
    # test trace_filter
    filtered = ew3_tracing.trace_filter({"fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"]})
    assert filtered == block_traces


def test_fail(cw3: CWeb3, ew3, ew3_tracing, conflux_side_contract, evm_side_contract):
    tx_hash = conflux_side_contract.functions.fail(evm_side_contract.address).transact({"gas": 100000, "storageLimit": 1000})
    try:
        cw3.cfx.wait_for_transaction_receipt(tx_hash)
    except:
        pass

    receipt = cw3.cfx.get_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 1

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 0

    # test trace_block and trace_filter
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert len(block_traces) == 0

    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert len(block_traces) == 0

    # Fixed: filtered should be empty array instead of null, uncomment after conflux_rust modified,
    filtered = ew3_tracing.trace_filter(
        {"fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"]}
    )
    assert filtered == block_traces


def test_subcallFail(cw3: CWeb3, ew3, ew3_tracing, conflux_side_contract, evm_side_contract):
    tx_hash = conflux_side_contract.functions.subcallFail(evm_side_contract.address).transact()
    receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 0

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 0

    # test trace_block and trace_filter
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert len(block_traces) == 0
    block_traces = ew3_tracing.trace_block({"blockHash": receipt["blockHash"]})
    assert len(block_traces) == 0
    # Fixed: filtered should be empty array instead of null, uncomment after conflux_rust modified,
    filtered = ew3_tracing.trace_filter(
        {"fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"]}
    )
    assert filtered == block_traces


def test_no_phantom_tx_if_tx_fail(cw3: CWeb3, ew3, ew3_tracing, conflux_side_contract, evm_side_contract):
    tx_hash = conflux_side_contract.functions.callEVMAndSetStorage(evm_side_contract.address, 1000).transact(
        {"storageLimit": 1, "gas": 100000}
    )
    try:
        receipt = cw3.cfx.wait_for_transaction_receipt(tx_hash)
    except:
        pass
    receipt = cw3.cfx.get_transaction_receipt(tx_hash)
    assert receipt["outcomeStatus"] == 1

    block = ew3.eth.get_block(receipt["blockHash"], True)
    txs = block["transactions"]
    assert len(txs) == 0

    # test trace_block and trace_filter
    block_traces = ew3_tracing.trace_block(receipt["epochNumber"])
    assert len(block_traces) == 0
