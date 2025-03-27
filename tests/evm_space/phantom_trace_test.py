#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import rlp

from conflux.utils import sha3 as keccak
from test_framework.util import *
from test_framework.mininode import *
from web3 import Web3
from base import Web3Base

CROSS_SPACE_CALL_PATH = "../contracts/CrossSpaceCall"
CROSS_SPACE_CALL_ADDRESS = "0x0888000000000000000000000000000000000006"

CONFLUX_CONTRACT_PATH = "../contracts/CrossSpaceTraceTest/CrossSpaceTraceTestConfluxSide"
EVM_CONTRACT_PATH = "../contracts/CrossSpaceTraceTest/CrossSpaceTraceTestEVMSide"

NULL_ADDRESS = "0x0000000000000000000000000000000000000000"

def encode_u256(number):
    return ("%x" % number).zfill(64)

def number_to_topic(number):
    return "0x" + encode_u256(number)

def mapped_address(hex_addr):
    return "0x" + keccak(bytes.fromhex(hex_addr.replace("0x", "")))[12:].hex()

class PhantomTransactionTest(Web3Base):
    def run_test(self):
        # initialize Conflux account
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.from_key(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

        # deploy Conflux space contract
        self.confluxContractAddr = self.deploy_conflux_space(CONFLUX_CONTRACT_PATH + ".bytecode")
        print(f'Conflux contract: {self.confluxContractAddr}')

        abi_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONFLUX_CONTRACT_PATH + ".abi")
        assert(os.path.isfile(abi_file))
        abi = open(abi_file).read()
        self.confluxContract = self.w3.eth.contract(abi=abi)

        # deploy EVM space contract
        self.evmContractAddr = self.deploy_evm_space(EVM_CONTRACT_PATH + ".bytecode")
        print(f'EVM contract: {self.evmContractAddr}')

        abi_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), EVM_CONTRACT_PATH + ".abi")
        assert(os.path.isfile(abi_file))
        abi = open(abi_file).read()
        self.evmContract = self.w3.eth.contract(abi=abi)

        # import CrossSpaceCall abi
        abi_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CROSS_SPACE_CALL_PATH + ".abi")
        assert(os.path.isfile(abi_file))
        abi = open(abi_file).read()
        self.crossSpaceContract = self.w3.eth.contract(abi=abi)

        # test traces
        self.test_callEVM()
        self.test_staticCallEVM()
        self.test_createEVM()
        self.test_transferEVM()
        self.test_withdrawFromMapped()
        self.test_fail()
        self.test_deployEip1820()

        self.log.info("Pass")

    def test_callEVM(self):
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="callEVM", args=[self.evmContractAddr, 1])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x0")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 2)

        # phantom #0: balance transfer to mapped account
        phantom0 = phantom_txs[0]

        assert_equal(phantom0["from"], NULL_ADDRESS)
        assert_equal(phantom0["to"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom0["input"], cfxTxHash + encode_u256(0))
        assert_equal(phantom0["gas"], "0x0")
        assert_equal(phantom0["gasPrice"], "0x0")
        assert_equal(phantom0["nonce"], "0x0")
        assert_equal(phantom0["status"], "0x1")
        assert_equal(phantom0["blockHash"], block["hash"])
        assert_equal(phantom0["blockNumber"], block["number"])
        assert_equal(phantom0["transactionIndex"], "0x0")

        trace0 = self.nodes[0].ethrpc.trace_transaction(phantom0["hash"])

        assert_equal(trace0, [{
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"],
                "gas": "0x0",
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": "0x0",
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": int(phantom0["blockNumber"], 16),
            "transactionHash": phantom0["hash"],
            "transactionPosition": int(phantom0["transactionIndex"], 16),
            "valid": True,
        }])

        # phantom #1: contract call from mapped account
        phantom1 = phantom_txs[1]

        assert_equal(phantom1["from"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom1["to"], self.evmContractAddr.lower())
        assert_equal(phantom1["input"], self.evmContract.encode_abi(abi_element_identifier="call", args=[1])),
        assert_equal(phantom1["status"], "0x1")
        assert_equal(phantom1["blockHash"], block["hash"])
        assert_equal(phantom1["blockNumber"], block["number"])
        assert_equal(phantom1["transactionIndex"], "0x1")

        trace1 = self.nodes[0].ethrpc.trace_transaction(phantom1["hash"])

        assert_equal(trace1, [{
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom1["from"],
                "to": phantom1["to"],
                "input": phantom1["input"],
                "gas": "0x0",
                "value": phantom1["value"],
            },
            "result": {
                "gasUsed": "0x0",
                "output": number_to_topic(1),
            },
            "subtraces": 1,
            "traceAddress": [],
            "blockHash": phantom1["blockHash"],
            "blockNumber": int(phantom1["blockNumber"], 16),
            "transactionHash": phantom1["hash"],
            "transactionPosition": int(phantom1["transactionIndex"], 16),
            "valid": True,
        }, {
            "type": "call",
            "action": {
                "callType": "call",
                "from": self.evmContractAddr.lower(),
                "to": self.evmContractAddr.lower(),
                "input": self.evmContract.encode_abi(abi_element_identifier="call", args=[0]),
                "gas": "0x0",
                "value": "0x0",
            },
            "result": {
                "gasUsed": "0x0",
                "output": number_to_topic(0),
            },
            "subtraces": 0,
            "traceAddress": [0],
            "blockHash": block["hash"],
            "blockNumber": int(block["number"], 16),
            "transactionHash": phantom_txs[1]["hash"],
            "transactionPosition": int(phantom1["transactionIndex"], 16),
            "valid": True,
        }])

        # test trace_block
        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(block_traces, trace0 + trace1)

        block_traces = self.nodes[0].ethrpc.trace_block({ "blockHash": receipt["blockHash"] })
        assert_equal(block_traces, trace0 + trace1)

        # test trace_filter
        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, block_traces)

        filtered = self.nodes[0].ethrpc.trace_filter({
            "fromAddress": [mapped_address(self.confluxContractAddr), self.evmContractAddr, NULL_ADDRESS],
            "toAddress":   [mapped_address(self.confluxContractAddr), self.evmContractAddr],
        })

        assert_equal(filtered, block_traces)

    def test_staticCallEVM(self):
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="staticCallEVM", args=[self.evmContractAddr, 1])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 0)

        # test trace_block
        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(block_traces, [])

        block_traces = self.nodes[0].ethrpc.trace_block({ "blockHash": receipt["blockHash"] })
        assert_equal(block_traces, [])

        # test trace_filter
        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, None) # we return `null` instead of `[]`

    def test_createEVM(self):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), EVM_CONTRACT_PATH + ".bytecode")
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        data_hex = self.confluxContract.encode_abi(abi_element_identifier="createEVM", args=[bytes.fromhex(bytecode)])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex, gas=3_700_000)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x0")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 2)

        # phantom #0: balance transfer to mapped account
        phantom0 = phantom_txs[0]

        assert_equal(phantom0["from"], NULL_ADDRESS)
        assert_equal(phantom0["to"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom0["input"], cfxTxHash + encode_u256(0))
        assert_equal(phantom0["gas"], "0x0")
        assert_equal(phantom0["gasPrice"], "0x0")
        assert_equal(phantom0["nonce"], "0x0")
        assert_equal(phantom0["status"], "0x1")
        assert_equal(phantom0["blockHash"], block["hash"])
        assert_equal(phantom0["blockNumber"], block["number"])
        assert_equal(phantom0["transactionIndex"], "0x0")

        trace0 = self.nodes[0].ethrpc.trace_transaction(phantom0["hash"])

        assert_equal(trace0, [{
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"],
                "gas": "0x0",
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": "0x0",
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": int(phantom0["blockNumber"], 16),
            "transactionHash": phantom0["hash"],
            "transactionPosition": int(phantom0["transactionIndex"], 16),
            "valid": True,
        }])

        # phantom #1: contract creation from mapped account
        phantom1 = phantom_txs[1]

        assert_equal(phantom1["from"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom1["to"], None)
        assert_equal(phantom1["input"], "0x" + bytecode)
        assert_equal(phantom1["status"], "0x1")
        assert_equal(phantom1["blockHash"], block["hash"])
        assert_equal(phantom1["blockNumber"], block["number"])
        assert_equal(phantom1["transactionIndex"], "0x1")

        # get contract addr from `Create` event
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        newContractAddr = receipt["logs"][0]["topics"][2][:42] # skip trailing 0's, keep 0x prefix

        trace1 = self.nodes[0].ethrpc.trace_transaction(phantom1["hash"])

        assert_equal(trace1, [{
            "type": "create",
            "action": {
                "createType": "create",
                "from": phantom1["from"],
                "init": phantom1["input"],
                "gas": "0x0",
                "value": phantom1["value"],
            },
            "result": {
                "address": newContractAddr,
                "gasUsed": "0x0",
                "code": "0x" + bytecode[64:],
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom1["blockHash"],
            "blockNumber": int(phantom1["blockNumber"], 16),
            "transactionHash": phantom1["hash"],
            "transactionPosition": int(phantom1["transactionIndex"], 16),
            "valid": True,
        }])

        # test trace_block
        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(block_traces, trace0 + trace1)

        block_traces = self.nodes[0].ethrpc.trace_block({ "blockHash": receipt["blockHash"] })
        assert_equal(block_traces, trace0 + trace1)

        # test trace_filter
        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, block_traces)

    def test_transferEVM(self):
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="transferEVM", args=[self.evmAccount.address])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex, value=0x222)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x0")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 4) # 2 internal contract calls, 2 phantom txs each

        # phantom #0: balance transfer to mapped account
        phantom0 = phantom_txs[0]

        assert_equal(phantom0["from"], NULL_ADDRESS)
        assert_equal(phantom0["to"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom0["input"], cfxTxHash + encode_u256(0))
        assert_equal(phantom0["gas"], "0x0")
        assert_equal(phantom0["gasPrice"], "0x0")
        assert_equal(phantom0["value"], "0x111")
        assert_equal(phantom0["nonce"], "0x0")
        assert_equal(phantom0["status"], "0x1")
        assert_equal(phantom0["blockHash"], block["hash"])
        assert_equal(phantom0["blockNumber"], block["number"])
        assert_equal(phantom0["transactionIndex"], "0x0")

        trace0 = self.nodes[0].ethrpc.trace_transaction(phantom0["hash"])

        assert_equal(trace0, [{
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"],
                "gas": "0x0",
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": "0x0",
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": int(phantom0["blockNumber"], 16),
            "transactionHash": phantom0["hash"],
            "transactionPosition": int(phantom0["transactionIndex"], 16),
            "valid": True,
        }])

        # phantom #1: contract call from mapped account
        phantom1 = phantom_txs[1]

        assert_equal(phantom1["from"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom1["to"], self.evmAccount.address.lower())
        assert_equal(phantom1["input"], "0x")
        assert_equal(phantom1["value"], "0x111")
        assert_equal(phantom1["status"], "0x1")
        assert_equal(phantom1["blockHash"], block["hash"])
        assert_equal(phantom1["blockNumber"], block["number"])
        assert_equal(phantom1["transactionIndex"], "0x1")

        trace1 = self.nodes[0].ethrpc.trace_transaction(phantom1["hash"])

        assert_equal(trace1, [{
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom1["from"],
                "to": phantom1["to"],
                "input": phantom1["input"],
                "gas": "0x0",
                "value": phantom1["value"],
            },
            "result": {
                "gasUsed": "0x0",
                "output": '0x',
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom1["blockHash"],
            "blockNumber": int(phantom1["blockNumber"], 16),
            "transactionHash": phantom1["hash"],
            "transactionPosition": int(phantom1["transactionIndex"], 16),
            "valid": True,
        }])

        # phantom #2: balance transfer to mapped account
        # this is the same as phantom #0, but `input` should use index 1 instead of 0
        phantom2 = phantom_txs[2]
        assert_equal(phantom2["input"], cfxTxHash + encode_u256(1))
        trace2 = self.nodes[0].ethrpc.trace_transaction(phantom2["hash"])
        assert_equal(trace2[0]["action"]["input"], phantom2["input"])

        # test trace_block
        trace2 = self.nodes[0].ethrpc.trace_transaction(phantom_txs[2]["hash"])
        trace3 = self.nodes[0].ethrpc.trace_transaction(phantom_txs[3]["hash"])

        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(block_traces, trace0 + trace1 + trace2 + trace3)

        block_traces = self.nodes[0].ethrpc.trace_block({ "blockHash": receipt["blockHash"] })
        assert_equal(block_traces, trace0 + trace1 + trace2 + trace3)

        # test trace_filter
        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, block_traces)

    def test_withdrawFromMapped(self):
        # withdraw with insufficient funds should fail
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="withdrawFromMapped", args=[0x123])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x1") # failure

        # transfer funds to mapped account
        receiver = Web3.to_checksum_address(mapped_address(self.confluxContractAddr))
        nonce = self.w3.eth.get_transaction_count(self.evmAccount.address)

        signed = self.evmAccount.sign_transaction({
            "to": receiver,
            "value": 0x123,
            "gasPrice": 1,
            "gas": 150000,
            "nonce": nonce,
            "chainId": 10,
            "data": data_hex,
        })

        self.w3.eth.send_raw_transaction(signed["raw_transaction"])
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.wait_for_transaction_receipt(signed["hash"])
        assert_equal(receipt["status"], 1) # success

        data_hex = self.confluxContract.encode_abi(abi_element_identifier="withdrawFromMapped", args=[0x123])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x0") # success

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 1)

        # phantom #0: balance transfer from mapped account
        phantom0 = phantom_txs[0]

        assert_equal(phantom0["from"], mapped_address(self.confluxContractAddr))
        assert_equal(phantom0["to"], NULL_ADDRESS)
        assert_equal(phantom0["input"], "0x")
        assert_equal(phantom0["gas"], "0x0")
        assert_equal(phantom0["gasPrice"], "0x0")
        assert_equal(phantom0["value"], "0x123")
        assert_equal(phantom0["status"], "0x1")
        assert_equal(phantom0["blockHash"], block["hash"])
        assert_equal(phantom0["blockNumber"], block["number"])
        assert_equal(phantom0["transactionIndex"], "0x0")

        # NOTE: nonce is >0 because callEVM and tranferToEVM used the mapped addr

        trace0 = self.nodes[0].ethrpc.trace_transaction(phantom0["hash"])

        assert_equal(trace0, [{
            "type": "call",
            "action": {
                "callType": "call",
                "from": phantom0["from"],
                "to": phantom0["to"],
                "input": phantom0["input"],
                "gas": "0x0",
                "value": phantom0["value"],
            },
            "result": {
                "gasUsed": "0x0",
                "output": "0x",
            },
            "subtraces": 0,
            "traceAddress": [],
            "blockHash": phantom0["blockHash"],
            "blockNumber": int(phantom0["blockNumber"], 16),
            "transactionHash": phantom0["hash"],
            "transactionPosition": int(phantom0["transactionIndex"], 16),
            "valid": True,
        }])

        # test trace_block
        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(block_traces, trace0)

        block_traces = self.nodes[0].ethrpc.trace_block({ "blockHash": receipt["blockHash"] })
        assert_equal(block_traces, trace0)

        # test trace_filter
        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, block_traces)

    def test_fail(self):
        # test failing tx
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="fail", args=[self.evmContractAddr])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x1")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 0)

        # test trace_block
        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(len(block_traces), 0)

        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(len(block_traces), 0)

        # test failing subcall
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="subcallFail", args=[self.evmContractAddr])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x0")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 0)

        # test trace_block
        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(len(block_traces), 0)

        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(len(block_traces), 0)

        # test trace_filter
        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, None)

        # test insufficient storage (issue #2483)
        data_hex = self.confluxContract.encode_abi(abi_element_identifier="callEVMAndSetStorage", args=[self.evmContractAddr, 1])
        tx = self.rpc.new_contract_tx(receiver=self.confluxContractAddr, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x1")

        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"]) # this should not fail
        assert_equal(len(block_traces), 0)

    def test_deployEip1820(self):
        data_hex = self.crossSpaceContract.encode_abi(abi_element_identifier="deployEip1820", args=[])
        tx = self.rpc.new_contract_tx(receiver=CROSS_SPACE_CALL_ADDRESS, data_hex=data_hex)
        cfxTxHash = tx.hash_hex()
        assert_equal(self.rpc.send_tx(tx, True), cfxTxHash)
        receipt = self.rpc.get_transaction_receipt(cfxTxHash)
        assert_equal(receipt["outcomeStatus"], "0x0")

        block = self.nodes[0].eth_getBlockByHash(receipt["blockHash"], True)
        phantom_txs = block["transactions"]
        assert_equal(len(phantom_txs), 0)

        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(len(block_traces), 0)

        block_traces = self.nodes[0].ethrpc.trace_block(receipt["epochNumber"])
        assert_equal(len(block_traces), 0)

        filtered = self.nodes[0].ethrpc.trace_filter({ "fromBlock": receipt["epochNumber"], "toBlock": receipt["epochNumber"] })
        assert_equal(filtered, None)

if __name__ == "__main__":
    PhantomTransactionTest().main()
