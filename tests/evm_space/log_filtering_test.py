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

class CrossSpaceLogFilteringTest(ConfluxTestFramework):
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

        def emitBoth(n):
            nonlocal cfx_next_nonce, cfx_tx_hashes
            data_hex = encode_hex_0x(keccak(b"emitBoth(uint256,bytes20)"))[:10] + encode_u256(n) + encode_bytes20(evmContractAddr.replace('0x', ''))
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
            emitBoth(12),
            emitEVM(13),
        ])

        block_b = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [
            emitConflux(14),
            emitBoth(15),
            emitEVM(16),
        ])

        block_c = self.rpc.generate_custom_block(parent_hash = block_b, referee = [], txs = [])

        block_d = self.rpc.generate_custom_block(parent_hash = block_a, referee = [], txs = [
            emitConflux(21),
            emitBoth(22),
            emitEVM(23),
        ])

        block_e = self.rpc.generate_custom_block(parent_hash = block_c, referee = [block_d], txs = [
            emitConflux(24),
            emitBoth(25),
            emitEVM(26),
        ])

        epoch_a = self.rpc.block_by_hash(block_a)['epochNumber']
        epoch_b = self.rpc.block_by_hash(block_b)['epochNumber']
        epoch_e = self.rpc.block_by_hash(block_e)['epochNumber']

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

        # check Conflux events
        filter = Filter(topics=[TEST_EVENT_TOPIC], from_epoch=epoch_a, to_epoch=epoch_e)
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 8)


        # --------------- 1 block per epoch ---------------
        # check EVM events
        # we expect 4 events: #12, #13, #15, #16
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": epoch_a, "toBlock": epoch_b }
        logs = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs), 4)

        # emitBoth: TestEvent(12)
        assert_equal(logs[0]["data"], number_to_topic(12))
        assert_equal(logs[0]["address"], evmContractAddr.lower())
        assert_equal(logs[0]["blockHash"], block_a)
        assert_equal(logs[0]["blockNumber"], epoch_a)
        assert_equal(logs[0]["transactionHash"], cfx_tx_hashes[1]) # TODO: should use phantom tx here
        # assert_equal(logs[0]["logIndex"], '0x0')
        # assert_equal(logs[0]["transactionIndex"], '0x0')
        # assert_equal(logs[0]["transactionLogIndex"], '0x0')
        assert_equal(logs[0]["removed"], False)

        # emitEVM: TestEvent(13)
        assert_equal(logs[1]["data"], number_to_topic(13))
        assert_equal(logs[1]["address"], evmContractAddr.lower())
        assert_equal(logs[1]["blockHash"], block_a)
        assert_equal(logs[1]["blockNumber"], epoch_a)
        assert_equal(logs[1]["transactionHash"], evm_tx_hashes[0].hex())
        # assert_equal(logs[1]["logIndex"], '0x1')
        # assert_equal(logs[1]["transactionIndex"], '0x1')
        assert_equal(logs[1]["transactionLogIndex"], '0x0')
        assert_equal(logs[1]["removed"], False)

        # emitBoth: TestEvent(15)
        assert_equal(logs[2]["data"], number_to_topic(15))
        assert_equal(logs[2]["address"], evmContractAddr.lower())
        assert_equal(logs[2]["blockHash"], block_b)
        assert_equal(logs[2]["blockNumber"], epoch_b)
        assert_equal(logs[2]["transactionHash"], cfx_tx_hashes[3]) # TODO: should use phantom tx here
        # assert_equal(logs[2]["logIndex"], '0x0')
        # assert_equal(logs[2]["transactionIndex"], '0x0')
        # assert_equal(logs[2]["transactionLogIndex"], '0x0')
        assert_equal(logs[2]["removed"], False)

        # emitEVM: TestEvent(16)
        assert_equal(logs[3]["data"], number_to_topic(16))
        assert_equal(logs[3]["address"], evmContractAddr.lower())
        assert_equal(logs[3]["blockHash"], block_b)
        assert_equal(logs[3]["blockNumber"], epoch_b)
        assert_equal(logs[3]["transactionHash"], evm_tx_hashes[1].hex())
        # assert_equal(logs[3]["logIndex"], '0x1')
        # assert_equal(logs[3]["transactionIndex"], '0x1')
        assert_equal(logs[3]["transactionLogIndex"], '0x0')
        assert_equal(logs[3]["removed"], False)


        # --------------- 2 blocks per epoch ---------------
        # check EVM events
        # we expect 4 events: #22, #23, #25, #26
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": epoch_e, "toBlock": epoch_e }
        logs = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs), 4)

        # emitBoth: TestEvent(22)
        assert_equal(logs[0]["data"], number_to_topic(22))
        assert_equal(logs[0]["address"], evmContractAddr.lower())
        assert_equal(logs[0]["blockHash"], block_e)
        assert_equal(logs[0]["blockNumber"], epoch_e)
        assert_equal(logs[0]["transactionHash"], cfx_tx_hashes[5]) # TODO: should use phantom tx here
        # assert_equal(logs[0]["logIndex"], '0x0')
        # assert_equal(logs[0]["transactionIndex"], '0x0')
        # assert_equal(logs[0]["transactionLogIndex"], '0x0')
        assert_equal(logs[0]["removed"], False)

        # emitEVM: TestEvent(23)
        assert_equal(logs[1]["data"], number_to_topic(23))
        assert_equal(logs[1]["address"], evmContractAddr.lower())
        assert_equal(logs[1]["blockHash"], block_e)
        assert_equal(logs[1]["blockNumber"], epoch_e)
        assert_equal(logs[1]["transactionHash"], evm_tx_hashes[2].hex())
        # assert_equal(logs[1]["logIndex"], '0x1')
        # assert_equal(logs[1]["transactionIndex"], '0x1')
        assert_equal(logs[1]["transactionLogIndex"], '0x0')
        assert_equal(logs[1]["removed"], False)

        # emitBoth: TestEvent(25)
        assert_equal(logs[2]["data"], number_to_topic(25))
        assert_equal(logs[2]["address"], evmContractAddr.lower())
        assert_equal(logs[2]["blockHash"], block_e)
        assert_equal(logs[2]["blockNumber"], epoch_e)
        assert_equal(logs[2]["transactionHash"], cfx_tx_hashes[7]) # TODO: should use phantom tx here
        # assert_equal(logs[2]["logIndex"], '0x2')
        # assert_equal(logs[2]["transactionIndex"], '0x2')
        # assert_equal(logs[2]["transactionLogIndex"], '0x0')
        assert_equal(logs[2]["removed"], False)

        # emitEVM: TestEvent(26)
        assert_equal(logs[3]["data"], number_to_topic(26))
        assert_equal(logs[3]["address"], evmContractAddr.lower())
        assert_equal(logs[3]["blockHash"], block_e)
        assert_equal(logs[3]["blockNumber"], epoch_e)
        assert_equal(logs[3]["transactionHash"], evm_tx_hashes[3].hex())
        # assert_equal(logs[3]["logIndex"], '0x3')
        # assert_equal(logs[3]["transactionIndex"], '0x3')
        assert_equal(logs[3]["transactionLogIndex"], '0x0')
        assert_equal(logs[3]["removed"], False)


        # --------------- other fields ---------------
        # filter by block hash
        filter = { "topics": [TEST_EVENT_TOPIC], "blockHash": block_c }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(logs_2, [])

        filter = { "topics": [TEST_EVENT_TOPIC], "blockHash": block_d } # from EVM perspective, D does not exist
        assert_raises_rpc_error(None, None, self.nodes[0].eth_getLogs, filter)

        filter = { "topics": [TEST_EVENT_TOPIC], "blockHash": block_e }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(logs_2, logs)

        # filter limit
        filter = { "topics": [TEST_EVENT_TOPIC], "blockHash": block_e, "limit": 1 }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(logs_2, [logs[-1]])

        # "earliest", "latest"
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": "earliest", "toBlock": "latest" }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs_2), 8)

        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": "earliest", "toBlock": "latest", "limit": 4 }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(logs_2, logs)

        # address
        filter = { "address": confluxContractAddr }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(logs_2, [])

        filter = { "address": evmContractAddr}
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs_2), 8)

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
    CrossSpaceLogFilteringTest().main()
