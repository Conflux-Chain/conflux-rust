#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils

from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *
from web3 import Web3

CONFLUX_CONTRACT_PATH = "../contracts/CrossSpaceEventTest/CrossSpaceEventTestConfluxSide.bytecode"
EVM_CONTRACT_PATH = "../contracts/CrossSpaceEventTest/CrossSpaceEventTestEVMSide.bytecode"

TEST_EVENT_TOPIC = encode_hex_0x(keccak(b"TestEvent(uint256)"))

def encode_u256(number):
    return ("%x" % number).zfill(64)

def encode_bytes20(hex):
    return hex.ljust(64, '0')

def number_to_topic(number):
    return "0x" + encode_u256(number)

class CrossSpaceLogFilteringTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["evm_chain_id"] = str(10)

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        ip = self.nodes[0].ip
        port = self.nodes[0].rpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))
        assert_equal(self.w3.isConnected(), True)

    def run_test(self):
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount('0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

        # deploy Conflux space contract
        confluxContractAddr = self.deploy_conflux_space(CONFLUX_CONTRACT_PATH)
        print(f'Conflux contract: {confluxContractAddr}')

        # deploy EVM space contract
        evmContractAddr = self.deploy_evm_space(EVM_CONTRACT_PATH)
        print(f'EVM contract: {evmContractAddr}')

        # #1: call emitConflux(1)
        # this will emit 1 event in the Conflux space
        data_hex = encode_hex_0x(keccak(b"emitConflux(uint256)"))[:10] + encode_u256(1)
        receipt = self.call_conflux_space(confluxContractAddr, data_hex)

        assert_equal(len(receipt["logs"]), 1)
        assert_equal(receipt["logs"][0]["data"], number_to_topic(1)) # TestEvent(1)

        # #2: call emitBoth(2)
        # this will emit 2 events in the Conflux space (our contract + internal contract) and 1 event in the EVM space
        data_hex = encode_hex_0x(keccak(b"emitBoth(uint256,bytes20)"))[:10] + encode_u256(2) + encode_bytes20(evmContractAddr.replace('0x', ''))
        receipt = self.call_conflux_space(confluxContractAddr, data_hex)

        assert_equal(len(receipt["logs"]), 2)
        assert_equal(receipt["logs"][0]["data"], number_to_topic(2)) # TestEvent(2)
        # NOTE: EVM-space events are not returned here

        # #3: call emitEVM(3)
        # this will emit 1 event in the EVM space
        data_hex = encode_hex_0x(keccak(b"emitEVM(uint256)"))[:10] + encode_u256(3)
        receipt = self.call_evm_space(evmContractAddr, data_hex)

        assert_equal(len(receipt["logs"]), 1)
        assert_equal(receipt["logs"][0]["data"], number_to_topic(3)) # TestEvent(3)
        # NOTE: EVM-space events are not returned here

        # check Conflux events
        # we expect two events from #1 and #2
        filter = Filter(topics=[TEST_EVENT_TOPIC], from_epoch="earliest", to_epoch="latest_state")
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 2)
        assert_equal(logs[0]["data"], number_to_topic(1)) # TestEvent(1)
        assert_equal(logs[1]["data"], number_to_topic(2)) # TestEvent(2)

        # check EVM events
        # we expect two events from #2 and #3
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": "earliest", "toBlock": "latest_state" }
        logs = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs), 2)

        assert_equal(logs[0]["data"], number_to_topic(2)) # TestEvent(2)
        assert_equal(logs[0]["address"], evmContractAddr.lower())
        assert_equal(logs[0]["removed"], False)

        assert_equal(logs[1]["data"], number_to_topic(3)) # TestEvent(3)
        assert_equal(logs[1]["address"], evmContractAddr.lower())
        assert_equal(logs[1]["removed"], False)

        # TODO(thegaram): add more detailed tests once we have more control over block production
        # - events in pivot and non-pivot blocks
        # - log.blockHash and log.blockNumber should correspond to pivot block
        # - logIndex, transactionIndex, transactionLogIndex

        self.log.info("Pass")

    def cross_space_transfer(self, to, value):
        to = to.replace('0x', '')

        tx = self.rpc.new_tx(
            value=value,
            receiver="0x0888000000000000000000000000000000000006",
            data=decode_hex(f"0xda8d5daf{to}000000000000000000000000"),
            nonce=self.rpc.get_nonce(self.cfxAccount),
            gas=1000000,
        )

        self.rpc.send_tx(tx, True)

    def deploy_conflux_space(self, bytecode_path):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), bytecode_path)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        tx = self.rpc.new_contract_tx(receiver="", data_hex=bytecode, sender=self.cfxAccount, priv_key=self.cfxPrivkey, storage_limit=20000)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        addr = receipt["contractCreated"]
        assert_is_hex_string(addr)
        return addr

    def call_conflux_space(self, receiver, data_hex):
        tx = self.rpc.new_contract_tx(
            receiver=receiver,
            data_hex=data_hex,
            sender=self.cfxAccount,
            priv_key=self.cfxPrivkey,
        )

        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        return receipt

    def deploy_evm_space(self, bytecode_path):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), bytecode_path)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)

        signed = self.evmAccount.signTransaction({
            "to": None,
            "value": 0,
            "gasPrice": 1,
            "gas": 210000,
            "nonce": nonce,
            "chainId": 10,
            "data": bytecode,
        })

        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        assert_equal(tx_hash, return_tx_hash)

        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        print(receipt)
        assert_equal(receipt["status"], 1)
        addr = receipt["contractAddress"]
        return addr

    def call_evm_space(self, to, data):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)

        signed = self.evmAccount.signTransaction({
            "to": to,
            "value": 0,
            "gasPrice": 1,
            "gas": 150000,
            "nonce": nonce,
            "chainId": 10,
            "data": data,
        })

        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        assert_equal(tx_hash, return_tx_hash)

        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        assert_equal(receipt["status"], 1)
        return receipt

if __name__ == "__main__":
    CrossSpaceLogFilteringTest().main()
