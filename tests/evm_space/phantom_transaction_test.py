#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import rlp

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

class PhantomTransactionTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["evm_chain_id"] = str(10)
        self.conf_parameters["evm_transaction_block_ratio"] = str(1)

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])

        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))
        assert_equal(self.w3.isConnected(), True)

    def run_test(self):
        # initialize Conflux account
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

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

        #                              ---
        #           .-----------------| D |....
        #           V                  ---    |
        #          ---      ---      ---      ---
        # ... <-- | A | <- | B | <- | C | <- | E | <- ...
        #          ---      ---      ---      ---
        #
        #                 A --- B --- C --- D --- E
        # block number    0  |  1  |  2  |  3  |  4  |
        # epoch number    0  |  1  |  2  |     3     |

        cfx_next_nonce = self.rpc.get_nonce(self.cfxAccount)
        cfx_tx_hashes = []

        evm_next_nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        evm_tx_hashes = []

        def emitConflux(n):
            nonlocal cfx_next_nonce, cfx_tx_hashes
            data_hex = (encode_hex_0x(keccak(b"emitConflux(uint256)"))[:10] + encode_u256(n))
            tx = self.rpc.new_contract_tx(receiver=confluxContractAddr, data_hex=data_hex, nonce = cfx_next_nonce, sender=self.cfxAccount, priv_key=self.cfxPrivkey)
            cfx_next_nonce += 1
            cfx_tx_hashes.append(tx.hash_hex())
            return tx

        def emitComplex(n):
            nonlocal cfx_next_nonce, cfx_tx_hashes
            data_hex = encode_hex_0x(keccak(b"emitComplex(uint256,bytes20)"))[:10] + encode_u256(n) + encode_bytes20(evmContractAddr.replace('0x', ''))
            tx = self.rpc.new_contract_tx(receiver=confluxContractAddr, data_hex=data_hex, nonce = cfx_next_nonce, sender=self.cfxAccount, priv_key=self.cfxPrivkey)
            cfx_next_nonce += 1
            cfx_tx_hashes.append(tx.hash_hex())
            return tx

        def emitEVM(n):
            nonlocal evm_next_nonce, evm_tx_hashes
            data_hex = (encode_hex_0x(keccak(b"emitEVM(uint256)"))[:10] + encode_u256(n))
            tx, hash = self.construct_evm_tx(receiver=evmContractAddr, data_hex=data_hex, nonce = evm_next_nonce)
            evm_next_nonce += 1
            evm_tx_hashes.append(hash)
            return tx

        # generate ledger
        block_0 = self.rpc.block_by_epoch("latest_mined")['hash']

        block_a = self.rpc.generate_custom_block(parent_hash = block_0, referee = [], txs = [
            emitConflux(11),
            emitEVM(12),
            emitComplex(13),
        ])

        block_b = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [
            emitConflux(14),
            emitEVM(15),
            emitComplex(16),
        ])

        block_c = self.rpc.generate_custom_block(parent_hash = block_b, referee = [], txs = [])

        block_d = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [
            emitConflux(21),
            emitEVM(22),
            emitComplex(23),
        ])

        block_e = self.rpc.generate_custom_block(parent_hash = block_c, referee = [block_d], txs = [
            emitConflux(24),
            emitEVM(25),
            emitComplex(26),
        ])

        [epoch_a, block_number_a] = [self.rpc.block_by_hash(block_a)[key] for key in ['epochNumber', 'blockNumber']]
        [epoch_b, block_number_b] = [self.rpc.block_by_hash(block_b)[key] for key in ['epochNumber', 'blockNumber']]
        [epoch_d, block_number_d] = [self.rpc.block_by_hash(block_d)[key] for key in ['epochNumber', 'blockNumber']]
        [epoch_e, block_number_e] = [self.rpc.block_by_hash(block_e)[key] for key in ['epochNumber', 'blockNumber']]

        # make sure transactions have been executed
        parent_hash = block_e

        for _ in range(5):
            block = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block

        for h in cfx_tx_hashes:
            receipt = self.rpc.get_transaction_receipt(h)
            assert_equal(receipt["outcomeStatus"], "0x0")

        for h in evm_tx_hashes:
            receipt = self.w3.eth.waitForTransactionReceipt(h)
            assert_equal(receipt["status"], 1)

        # TODO: add failing tx

        # ---------------------------------------------------------------------

        # Conflux perspective:
        # A: 2 txs (events: [11], [13, X, X, 13, X, X, 13])  X ~ internal contract event
        # B: 2 txs (events: [14], [16, X, X, 16, X, X, 16])
        # C: /
        # D: 2 txs (events: [21], [23, X, X, 23, X, X, 23])
        # E: 2 txs (events: [24], [26, X, X, 26, X, X, 26])

        # block #A
        block = self.nodes[0].cfx_getBlockByHash(block_a, True)
        assert_equal(len(block["transactions"]), 2)

        block2 = self.nodes[0].cfx_getBlockByBlockNumber(block_number_a, True)
        assert_equal(block2, block)

        tx_hashes = self.nodes[0].cfx_getBlockByHash(block_a, False)["transactions"]
        assert_equal(len(tx_hashes), 2)

        for idx, tx in enumerate(block["transactions"]):
            # check returned hash
            assert_equal(tx["hash"], tx_hashes[idx])

            # check indexing
            # assert_equal(tx["transactionIndex"], hex(idx))

            # check cfx_getTransactionByHash
            assert_equal(tx, self.nodes[0].cfx_getTransactionByHash(tx["hash"]))

        receipts = self.nodes[0].cfx_getEpochReceipts(epoch_a)
        assert_equal(len(receipts), 1)    # 1 block
        assert_equal(len(receipts[0]), 2) # 2 receipts

        receipts2 = self.nodes[0].cfx_getEpochReceipts(f'hash:{block_a}')
        assert_equal(receipts2, receipts)

        assert_equal(len(receipts[0][0]["logs"]), 1)
        assert_equal(receipts[0][0]["logs"][0]["data"], number_to_topic(11))

        assert_equal(len(receipts[0][1]["logs"]), 7)
        assert_equal(receipts[0][1]["logs"][0]["data"], number_to_topic(13))
        # Call, Outcome, ...
        assert_equal(receipts[0][1]["logs"][3]["data"], number_to_topic(13))
        # Call, Outcome, ...
        assert_equal(receipts[0][1]["logs"][6]["data"], number_to_topic(13))

        # TODO....

        # ---------------------------------------------------------------------

        # EVM perspective:
        # A: 7 txs (events: [12], [], [], [13, 13], [], [], [13, 13])
        # B: 7 txs (events: [15], [], [], [16, 16], [], [], [16, 16])
        # C: /
        # E: 14 txs (events: [22], [], [], [23, 23], [], [], [23, 23], [25], [], [], [26, 26], [], [], [26, 26])

        # block #A
        block = self.nodes[0].eth_getBlockByNumber(epoch_a, True)
        assert_equal(len(block["transactions"]), 7)

        block2 = self.nodes[0].eth_getBlockByHash(block_a, True)
        assert_equal(block2, block)

        tx_hashes = self.nodes[0].eth_getBlockByNumber(epoch_a, False)["transactions"]
        assert_equal(len(tx_hashes), 7)

        for idx, tx in enumerate(block["transactions"]):
            # check returned hash
            assert_equal(tx["hash"], tx_hashes[idx])

            # check indexing
            assert_equal(tx["transactionIndex"], hex(idx))

            # check eth_getTransactionByHash
            # assert_equal(tx, self.nodes[0].eth_getTransactionByHash(tx["hash"]))

        # TODO: check transaction details
        # TODO: check receipts

        # block #D
        block = self.nodes[0].eth_getBlockByHash(block_d, True)
        assert_equal(block, None)

        # block #E
        block = self.nodes[0].eth_getBlockByNumber(epoch_e, True)
        assert_equal(len(block["transactions"]), 14)

        block2 = self.nodes[0].eth_getBlockByHash(block_e, True)
        assert_equal(block2, block)

        tx_hashes = self.nodes[0].eth_getBlockByNumber(epoch_e, False)["transactions"]
        assert_equal(len(tx_hashes), 14)

        for idx, tx in enumerate(block["transactions"]):
            # check returned hash
            assert_equal(tx["hash"], tx_hashes[idx])

            # check indexing
            assert_equal(tx["transactionIndex"], hex(idx))

            # check eth_getTransactionByHash
            # assert_equal(tx, self.nodes[0].eth_getTransactionByHash(tx["hash"]))

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

    def deploy_evm_space(self, bytecode_path):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), bytecode_path)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)

        signed = self.evmAccount.signTransaction({
            "to": None,
            "value": 0,
            "gasPrice": 1,
            "gas": 500000,
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
        assert_equal(receipt["status"], 1)
        addr = receipt["contractAddress"]
        return addr

    def construct_evm_tx(self, receiver, data_hex, nonce):
        signed = self.evmAccount.signTransaction({
            "to": receiver,
            "value": 0,
            "gasPrice": 1,
            "gas": 150000,
            "nonce": nonce,
            "chainId": 10,
            "data": data_hex,
        })

        tx = [nonce, 1, 150000, bytes.fromhex(receiver.replace('0x', '')), 0, bytes.fromhex(data_hex.replace('0x', '')), signed["v"], signed["r"], signed["s"]]
        return tx, signed["hash"]

if __name__ == "__main__":
    PhantomTransactionTest().main()
