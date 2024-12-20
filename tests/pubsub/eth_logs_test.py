#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, time
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import asyncio
import eth_utils

from eth_utils import decode_hex
from conflux.config import default_config
from conflux.pubsub import PubSubClient
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, priv_to_addr, bytes_to_int
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_ne, assert_is_hex_string, connect_nodes, sync_blocks
from web3 import Web3

FULLNODE0 = 0
FULLNODE1 = 1

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"foo()"))

NUM_CALLS = 20

# default test account's private key
DEFAULT_TEST_ACCOUNT_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

class PubSubTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '200'

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])

        # set up PubSub clients
        self.pubsub = [None] * self.num_nodes
        self.pubsub[FULLNODE0] = PubSubClient(self.nodes[FULLNODE0], True)
        self.pubsub[FULLNODE1] = PubSubClient(self.nodes[FULLNODE1], True)

        self.core_pubsub = [None] * self.num_nodes
        self.core_pubsub[FULLNODE0] = PubSubClient(self.nodes[FULLNODE0])
        self.core_pubsub[FULLNODE1] = PubSubClient(self.nodes[FULLNODE1])

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    def cross_space_transfer(self, to, value):
        to = to.replace('0x', '')

        tx = self.rpc[FULLNODE0].new_tx(
            value=value,
            receiver="0x0888000000000000000000000000000000000006",
            data=decode_hex(f"0xda8d5daf{to}000000000000000000000000"),
            nonce=self.rpc[FULLNODE0].get_nonce(self.cfxAccount),
            gas=1000000,
        )

        self.rpc[FULLNODE0].send_tx(tx, True)

    async def run_async(self):
        # initialize Conflux account
        priv_key = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc[FULLNODE0].GENESIS_ADDR
        self.setup_w3()
        self.w3 = self.ew3
        assert_equal(self.w3.is_connected(), True)

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.from_key(DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 1 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

        # deploy two instances of the contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        _, contract1 = self.deploy_evm_space(bytecode)
        _, contract2 = self.deploy_evm_space(bytecode)

        # subscribe
        sub_all = await self.pubsub[FULLNODE0].subscribe("logs")
        sub_one = await self.pubsub[FULLNODE0].subscribe("logs", { "address": contract2 })

        sub_all_core = await self.core_pubsub[FULLNODE0].subscribe("logs")

        # call contracts and collect receipts
        receipts = []

        for _ in range(NUM_CALLS):
            r = self.call_contract(contract1, FOO_TOPIC)
            assert(r != None)
            receipts.append(r)

            r = self.call_contract(contract2, FOO_TOPIC)
            receipts.append(r)
            assert(r != None)

        sync_blocks(self.nodes)

        # collect pub-sub notifications
        logs1 = [l async for l in sub_all.iter()]
        logs2 = [l async for l in sub_one.iter()]

        assert_equal(len([l async for l in sub_all_core.iter()]), 0)
        assert_equal(len(logs1), 2 * NUM_CALLS)
        assert_equal(len(logs2), NUM_CALLS)

        self.log.info(f"Pass -- retrieved logs with no fork")

        # create alternative fork
        old_tip = self.rpc[FULLNODE0].best_block_hash()
        old_tip_epoch = self.rpc[FULLNODE0].epoch_number()
        fork_hash = receipts[len(receipts) // 2]["blockHash"]
        fork_epoch = int(receipts[len(receipts) // 2]["blockNumber"], 16)

        self.log.info(f"Creating fork at {fork_hash[:20]}... (#{fork_epoch})")

        new_tip = self.generate_chain(fork_hash, 2 * (old_tip_epoch - fork_epoch))[-1]
        new_tip = self.rpc[FULLNODE0].generate_block_with_parent(new_tip, referee = [old_tip])
        new_tip = self.generate_chain(new_tip, 20)[-1]
        new_tip_epoch = self.rpc[FULLNODE0].epoch_number()
        sync_blocks(self.nodes)

        self.log.info(f"Tip: {old_tip[:20]}... (#{old_tip_epoch}) --> {new_tip[:20]}... (#{new_tip_epoch})")

        # block order changed, some transactions need to be re-executed
        num_to_reexecute = sum(1 for r in receipts if int(r["blockNumber"], 16) > fork_epoch)

        logs = [l async for l in sub_all.iter()]
        assert_equal(len(logs), num_to_reexecute * 2)
        assert_equal(len([l async for l in sub_all_core.iter()]), 1)

        for i in range(num_to_reexecute):
            assert(logs[i]["removed"])
        
        for i in range(num_to_reexecute, num_to_reexecute * 2):
            assert(logs[i]["removed"] == False)

        self.log.info(f"Pass -- retrieved re-executed logs after fork")

        # create one transaction that is mined but not executed yet
        sync_blocks(self.nodes)

        nonce = self.w3.eth.get_transaction_count(self.evmAccount.address)
        signed = self.evmAccount.sign_transaction({
            "to": contract1,
            "value": 0,
            "gasPrice": 1,
            "gas": 500000,
            "nonce": nonce,
            "chainId": 10,
            "data": FOO_TOPIC
        })

        tx = self.w3.eth.send_raw_transaction(signed["raw_transaction"]).hex()
        assert_equal(signed.hash.hex(), tx)

        self.rpc[FULLNODE0].generate_block(num_txs=1)

        receipt = self.nodes[0].eth_getTransactionReceipt(tx)
        assert_equal(receipt, None)

        time.sleep(1)

        # mine more blocks, the transaction is now executed
        self.rpc[FULLNODE0].generate_blocks(4)
        receipt = self.nodes[0].eth_getTransactionReceipt(tx)
        assert_ne(receipt, None)
        sync_blocks(self.nodes)

        # this would timeout before #1989 was fixed
        await sub_all.next()

        self.log.info(f"Pass -- test #1989 fix")

    def run_test(self):
        asyncio.run(self.run_async())

    def deploy_evm_space(self, data_hex):
        nonce = self.w3.eth.get_transaction_count(self.evmAccount.address)

        signed = self.evmAccount.sign_transaction({
            "to": None,
            "value": 0,
            "gasPrice": 1,
            "gas": 500000,
            "nonce": nonce,
            "chainId": 10,
            "data": data_hex,
        })

        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.send_raw_transaction(signed["raw_transaction"])
        assert_equal(tx_hash, return_tx_hash)

        self.rpc[FULLNODE0].generate_block(1)
        self.rpc[FULLNODE0].generate_blocks(20, 1)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        assert_equal(receipt["status"], 1)
        addr = receipt["contractAddress"]
        return receipt, addr
    
    def call_contract(self, contract, data_hex):
        nonce = self.w3.eth.get_transaction_count(self.evmAccount.address)
        signed = self.evmAccount.sign_transaction({
            "to": contract,
            "value": 0,
            "gasPrice": 1,
            "gas": 500000,
            "nonce": nonce,
            "chainId": 10,
            "data": data_hex
        })

        tx = self.w3.eth.send_raw_transaction(signed["raw_transaction"]).hex()
        time_end = time.time() + 10
        while time.time() < time_end:
            self.rpc[FULLNODE0].generate_block(1)
            receipt = self.nodes[0].eth_getTransactionReceipt(tx)
            if receipt:
                return receipt
            
            time.sleep(0.5)
        
        return None

    def generate_chain(self, parent, len):
        hashes = [parent]
        for _ in range(len):
            hash = self.rpc[FULLNODE0].generate_block_with_parent(hashes[-1])
            hashes.append(hash)
        return hashes[1:]

if __name__ == "__main__":
    PubSubTest().main()
