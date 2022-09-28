#!/usr/bin/env python3

import os, sys, time

sys.path.insert(1, os.path.join(sys.path[0], ".."))

import asyncio

from eth_utils import decode_hex
from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak
from test_framework.blocktools import encode_hex_0x
from test_framework.util import assert_equal, connect_nodes, sync_blocks
from web3 import Web3
from base import Web3Base

FULLNODE0 = 0
FULLNODE1 = 1

CONTRACT_PATH = "../contracts/EventsTestContract_bytecode.dat"
FOO_TOPIC = encode_hex_0x(keccak(b"foo()"))

NUM_CALLS = 20

# default test account's private key
DEFAULT_TEST_ACCOUNT_KEY = (
    "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)


class FilterLogTest(Web3Base):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = "200"
        self.conf_parameters["poll_lifetime_in_seconds"] = "180"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    def cross_space_transfer(self, to, value):
        to = to.replace("0x", "")

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
        priv_key = default_config["GENESIS_PRI_KEY"]
        self.cfxAccount = self.rpc[FULLNODE0].GENESIS_ADDR

        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f"http://{ip}:{port}/"))
        assert_equal(self.w3.isConnected(), True)

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(
            DEFAULT_TEST_ACCOUNT_KEY
        )
        print(f"Using EVM account {self.evmAccount.address}")
        self.cross_space_transfer(self.evmAccount.address, 1 * 10**18)
        assert_equal(
            self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10**18)
        )

        # deploy two instances of the contract
        bytecode_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH
        )
        assert os.path.isfile(bytecode_file)
        bytecode = open(bytecode_file).read()
        _, contract1 = self.deploy_evm_space(bytecode)
        _, contract2 = self.deploy_evm_space(bytecode)

        filter = {"address": contract1, "fromBlock": "0x00"}
        filter1 = self.nodes[0].eth_newFilter(filter)
        filter2 = self.nodes[0].eth_newFilter({"fromBlock": "0x00"})

        logs1 = self.nodes[0].eth_getFilterChanges(filter1)
        logs2 = self.nodes[0].eth_getFilterChanges(filter2)
        assert_equal(len(logs1), 0)
        assert_equal(len(logs2), 0)

        # call contracts and collect receipts
        receipts = []
        for _ in range(NUM_CALLS):
            r = self.call_contract(contract1, FOO_TOPIC)
            assert r != None
            receipts.append(r)

            r = self.call_contract(contract2, FOO_TOPIC)
            receipts.append(r)
            assert r != None

        sync_blocks(self.nodes)

        # collect logs
        logs1 = self.nodes[0].eth_getFilterChanges(filter1)
        logs2 = self.nodes[0].eth_getFilterChanges(filter2)
        assert_equal(len(logs1), NUM_CALLS)
        assert_equal(len(logs2), 2 * NUM_CALLS)

        logs1 = self.nodes[0].eth_getFilterChanges(filter1)
        logs2 = self.nodes[0].eth_getFilterChanges(filter2)
        assert_equal(len(logs1), 0)
        assert_equal(len(logs2), 0)

        self.log.info(f"Pass -- filter logs with no fork")

        # create alternative fork
        old_tip = self.rpc[FULLNODE0].best_block_hash()
        old_tip_epoch = self.rpc[FULLNODE0].epoch_number()
        fork_hash = receipts[len(receipts) // 2]["blockHash"]
        fork_epoch = int(receipts[len(receipts) // 2]["blockNumber"], 16)

        self.log.info(f"Creating fork at {fork_hash[:20]}... (#{fork_epoch})")

        new_tip = self.generate_chain(fork_hash, 2 * (old_tip_epoch - fork_epoch))[-1]
        new_tip = self.rpc[FULLNODE0].generate_block_with_parent(
            new_tip, referee=[old_tip]
        )
        new_tip = self.generate_chain(new_tip, 20)[-1]
        new_tip_epoch = self.rpc[FULLNODE0].epoch_number()
        sync_blocks(self.nodes)

        self.log.info(
            f"Tip: {old_tip[:20]}... (#{old_tip_epoch}) --> {new_tip[:20]}... (#{new_tip_epoch})"
        )

        # block order changed, some transactions need to be re-executed
        num_to_reexecute = sum(
            1 for r in receipts if int(r["blockNumber"], 16) > fork_epoch
        )

        logs1 = self.nodes[0].eth_getFilterChanges(filter1)
        logs2 = self.nodes[0].eth_getFilterChanges(filter2)
        assert_equal(len(logs2), num_to_reexecute * 2)
        for i in range(num_to_reexecute):
            assert logs2[i]["removed"]

        for i in range(num_to_reexecute, num_to_reexecute * 2):
            assert logs2[i]["removed"] == False

        # call eth_getFilterLogs API
        logs1 = self.nodes[0].eth_getFilterLogs(filter1)
        logs2 = self.nodes[0].eth_getFilterLogs(filter2)
        assert_equal(len(logs1), NUM_CALLS + 1)
        assert_equal(len(logs2), 2 * NUM_CALLS + 2)

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())

    def deploy_evm_space(self, data_hex):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)

        signed = self.evmAccount.signTransaction(
            {
                "to": None,
                "value": 0,
                "gasPrice": 1,
                "gas": 500000,
                "nonce": nonce,
                "chainId": 10,
                "data": data_hex,
            }
        )

        tx_hash = signed["hash"]
        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        assert_equal(tx_hash, return_tx_hash)

        self.rpc[FULLNODE0].generate_block(1)
        self.rpc[FULLNODE0].generate_blocks(20, 1)
        receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        assert_equal(receipt["status"], 1)
        addr = receipt["contractAddress"]
        return receipt, addr

    def call_contract(self, contract, data_hex):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        signed = self.evmAccount.signTransaction(
            {
                "to": contract,
                "value": 0,
                "gasPrice": 1,
                "gas": 500000,
                "nonce": nonce,
                "chainId": 10,
                "data": data_hex,
            }
        )

        tx = self.w3.eth.sendRawTransaction(signed["rawTransaction"]).hex()
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
    FilterLogTest().main()
