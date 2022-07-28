#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import rlp

from conflux.filter import Filter
from conflux.utils import sha3 as keccak, priv_to_addr
from test_framework.blocktools import encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.util import *
from test_framework.mininode import *
from base import Web3Base

CONFLUX_CONTRACT_PATH = "../contracts/CrossSpaceEventTest/CrossSpaceEventTestConfluxSide.bytecode"
EVM_CONTRACT_PATH = "../contracts/CrossSpaceEventTest/CrossSpaceEventTestEVMSide.bytecode"

TEST_EVENT_TOPIC = encode_hex_0x(keccak(b"TestEvent(uint256)"))
CALL_EVENT_TOPIC = encode_hex_0x(keccak(b"Call(bytes20,bytes20,uint256,uint256,bytes)"))
OUTCOME_EVENT_TOPIC = encode_hex_0x(keccak(b"Outcome(bool)"))

def encode_u256(number):
    return ("%x" % number).zfill(64)

def encode_bytes20(hex):
    return hex.ljust(64, '0')

def number_to_topic(number):
    return "0x" + encode_u256(number)

class CrossSpaceLogFilteringTest(Web3Base):
    def run_test(self):
        # initialize Conflux account
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
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
        # 11, 12, X, X, 14, 15, X, X, 21, 22, X, X, 24, 25, X, X   (X ~ internal contract event)
        filter = Filter(from_epoch=epoch_a, to_epoch=epoch_e)
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 16)

        filter = Filter(topics=[CALL_EVENT_TOPIC], from_epoch=epoch_a, to_epoch=epoch_e)
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 4)

        filter = Filter(topics=[OUTCOME_EVENT_TOPIC], from_epoch=epoch_a, to_epoch=epoch_e)
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 4)

        filter = Filter(topics=[TEST_EVENT_TOPIC], from_epoch=epoch_a, to_epoch=epoch_e)
        logs = self.rpc.get_logs(filter)
        assert_equal(len(logs), 8)

        assert_equal(logs[0]["data"], number_to_topic(11))
        assert_equal(logs[0]["blockHash"], block_a)
        assert_equal(logs[0]["logIndex"], '0x0')
        assert_equal(logs[0]["transactionIndex"], '0x0')
        assert_equal(logs[0]["transactionLogIndex"], '0x0')

        assert_equal(logs[1]["data"], number_to_topic(12))
        assert_equal(logs[1]["blockHash"], block_a)
        assert_equal(logs[1]["logIndex"], '0x1')
        assert_equal(logs[1]["transactionIndex"], '0x1')
        assert_equal(logs[1]["transactionLogIndex"], '0x0')

        assert_equal(logs[2]["data"], number_to_topic(14))
        assert_equal(logs[2]["blockHash"], block_b)
        assert_equal(logs[2]["logIndex"], '0x0')
        assert_equal(logs[2]["transactionIndex"], '0x0')
        assert_equal(logs[2]["transactionLogIndex"], '0x0')

        assert_equal(logs[3]["data"], number_to_topic(15))
        assert_equal(logs[3]["blockHash"], block_b)
        assert_equal(logs[3]["logIndex"], '0x1')
        assert_equal(logs[3]["transactionIndex"], '0x1')
        assert_equal(logs[3]["transactionLogIndex"], '0x0')

        assert_equal(logs[4]["data"], number_to_topic(21))
        assert_equal(logs[4]["blockHash"], block_d)
        assert_equal(logs[4]["logIndex"], '0x0')
        assert_equal(logs[4]["transactionIndex"], '0x0')
        assert_equal(logs[4]["transactionLogIndex"], '0x0')

        assert_equal(logs[5]["data"], number_to_topic(22))
        assert_equal(logs[5]["blockHash"], block_d)
        assert_equal(logs[5]["logIndex"], '0x1')
        assert_equal(logs[5]["transactionIndex"], '0x1')
        assert_equal(logs[5]["transactionLogIndex"], '0x0')

        assert_equal(logs[6]["data"], number_to_topic(24))
        assert_equal(logs[6]["blockHash"], block_e)
        assert_equal(logs[6]["logIndex"], '0x0')
        assert_equal(logs[6]["transactionIndex"], '0x0')
        assert_equal(logs[6]["transactionLogIndex"], '0x0')

        assert_equal(logs[7]["data"], number_to_topic(25))
        assert_equal(logs[7]["blockHash"], block_e)
        assert_equal(logs[7]["logIndex"], '0x1')
        assert_equal(logs[7]["transactionIndex"], '0x1')
        assert_equal(logs[7]["transactionLogIndex"], '0x0')


        # --------------- 1 block per epoch ---------------
        # check EVM events
        # block A
        #   3 transactions: phantom (balance), phantom (cross-call), evm
        #   2 events: #12, #13
        # block B
        #   3 transactions: phantom (balance), phantom (cross-call), evm
        #   2 events: #15, #16
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": epoch_a, "toBlock": epoch_b }
        logs = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs), 4)

        block_a_txs_evm = self.nodes[0].eth_getBlockByHash(block_a, False)["transactions"]
        block_b_txs_evm = self.nodes[0].eth_getBlockByHash(block_b, False)["transactions"]

        # emitBoth: TestEvent(12)
        assert_equal(logs[0]["data"], number_to_topic(12))
        assert_equal(logs[0]["address"], evmContractAddr.lower())
        assert_equal(logs[0]["blockHash"], block_a)
        assert_equal(logs[0]["blockNumber"], epoch_a)
        assert_equal(logs[0]["transactionHash"], block_a_txs_evm[1]) # NOTE: #0 is balance transfer
        assert_equal(logs[0]["logIndex"], '0x0')
        assert_equal(logs[0]["transactionIndex"], '0x1')
        assert_equal(logs[0]["transactionLogIndex"], '0x0')
        assert_equal(logs[0]["removed"], False)

        # emitEVM: TestEvent(13)
        assert_equal(logs[1]["data"], number_to_topic(13))
        assert_equal(logs[1]["address"], evmContractAddr.lower())
        assert_equal(logs[1]["blockHash"], block_a)
        assert_equal(logs[1]["blockNumber"], epoch_a)
        assert_equal(logs[1]["transactionHash"], block_a_txs_evm[2])
        assert_equal(logs[1]["logIndex"], '0x1')
        assert_equal(logs[1]["transactionIndex"], '0x2')
        assert_equal(logs[1]["transactionLogIndex"], '0x0')
        assert_equal(logs[1]["removed"], False)

        # emitBoth: TestEvent(15)
        assert_equal(logs[2]["data"], number_to_topic(15))
        assert_equal(logs[2]["address"], evmContractAddr.lower())
        assert_equal(logs[2]["blockHash"], block_b)
        assert_equal(logs[2]["blockNumber"], epoch_b)
        assert_equal(logs[2]["transactionHash"], block_b_txs_evm[1])
        assert_equal(logs[2]["logIndex"], '0x0')
        assert_equal(logs[2]["transactionIndex"], '0x1')
        assert_equal(logs[2]["transactionLogIndex"], '0x0')
        assert_equal(logs[2]["removed"], False)

        # emitEVM: TestEvent(16)
        assert_equal(logs[3]["data"], number_to_topic(16))
        assert_equal(logs[3]["address"], evmContractAddr.lower())
        assert_equal(logs[3]["blockHash"], block_b)
        assert_equal(logs[3]["blockNumber"], epoch_b)
        assert_equal(logs[3]["transactionHash"], block_b_txs_evm[2])
        assert_equal(logs[3]["logIndex"], '0x1')
        assert_equal(logs[3]["transactionIndex"], '0x2')
        assert_equal(logs[3]["transactionLogIndex"], '0x0')
        assert_equal(logs[3]["removed"], False)


        # --------------- 2 blocks per epoch ---------------
        # check EVM events
        # block E
        #   6 transactions: phantom (balance), phantom (cross-call), evm, phantom (balance), phantom (cross-call), evm
        #   4 events: #22, #23, #25, #26
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": epoch_e, "toBlock": epoch_e }
        logs = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs), 4)

        block_e_txs_evm = self.nodes[0].eth_getBlockByHash(block_e, False)["transactions"]

        # emitBoth: TestEvent(22)
        assert_equal(logs[0]["data"], number_to_topic(22))
        assert_equal(logs[0]["address"], evmContractAddr.lower())
        assert_equal(logs[0]["blockHash"], block_e)
        assert_equal(logs[0]["blockNumber"], epoch_e)
        assert_equal(logs[0]["transactionHash"], block_e_txs_evm[1]) # NOTE: #0 is balance transfer
        assert_equal(logs[0]["logIndex"], '0x0')
        assert_equal(logs[0]["transactionIndex"], '0x1')
        assert_equal(logs[0]["transactionLogIndex"], '0x0')
        assert_equal(logs[0]["removed"], False)

        # emitEVM: TestEvent(23)
        assert_equal(logs[1]["data"], number_to_topic(23))
        assert_equal(logs[1]["address"], evmContractAddr.lower())
        assert_equal(logs[1]["blockHash"], block_e)
        assert_equal(logs[1]["blockNumber"], epoch_e)
        assert_equal(logs[1]["transactionHash"], block_e_txs_evm[2])
        assert_equal(logs[1]["logIndex"], '0x1')
        assert_equal(logs[1]["transactionIndex"], '0x2')
        assert_equal(logs[1]["transactionLogIndex"], '0x0')
        assert_equal(logs[1]["removed"], False)

        # emitBoth: TestEvent(25)
        assert_equal(logs[2]["data"], number_to_topic(25))
        assert_equal(logs[2]["address"], evmContractAddr.lower())
        assert_equal(logs[2]["blockHash"], block_e)
        assert_equal(logs[2]["blockNumber"], epoch_e)
        assert_equal(logs[2]["transactionHash"], block_e_txs_evm[4]) # NOTE: #3 is balance transfer
        assert_equal(logs[2]["logIndex"], '0x2')
        assert_equal(logs[2]["transactionIndex"], '0x4')
        assert_equal(logs[2]["transactionLogIndex"], '0x0')
        assert_equal(logs[2]["removed"], False)

        # emitEVM: TestEvent(26)
        assert_equal(logs[3]["data"], number_to_topic(26))
        assert_equal(logs[3]["address"], evmContractAddr.lower())
        assert_equal(logs[3]["blockHash"], block_e)
        assert_equal(logs[3]["blockNumber"], epoch_e)
        assert_equal(logs[3]["transactionHash"], block_e_txs_evm[5])
        assert_equal(logs[3]["logIndex"], '0x3')
        assert_equal(logs[3]["transactionIndex"], '0x5')
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

        # "earliest", "latest"
        filter = { "topics": [TEST_EVENT_TOPIC], "fromBlock": "earliest", "toBlock": "latest" }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs_2), 8)

        # address
        filter = { "fromBlock": "0x00", "address": confluxContractAddr }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(logs_2, [])

        filter = { "fromBlock": "0x00", "address": evmContractAddr }
        logs_2 = self.nodes[0].eth_getLogs(filter)
        assert_equal(len(logs_2), 8)

        # get-logs-filter-max-limit should limit the number of logs returned.
        self.stop_node(0)
        self.start_node(0, ["--get-logs-filter-max-limit", str(7)])

        # len(res) > max_limit: raise error
        filter = { "fromBlock": "0x00", "address": evmContractAddr }
        assert_raises_rpc_error(None, None, self.nodes[0].eth_getLogs, filter)

        # get-logs-filter-max-epoch-range should limit the number of epochs queried.
        self.stop_node(0)
        self.start_node(0, ["--get-logs-filter-max-epoch-range", "16"])
        filter = { "fromBlock": "0x00", "toBlock": "0x0f", "topics": [TEST_EVENT_TOPIC] }
        # should not raise error
        self.nodes[0].eth_getLogs(filter)
        filter = { "fromBlock": "0x00", "toBlock": "0x10", "topics": [TEST_EVENT_TOPIC] }
        assert_raises_rpc_error(None, None, self.nodes[0].eth_getLogs, filter)

        # check EIP-1898 support for eth_call: support both block number and block hash param
        call_request = { "to": evmContractAddr, "data": "0x42cbb15c" } # keccak("getBlockNumber()") = 0x42cbb15c

        res1 = self.nodes[0].eth_call(call_request, epoch_a)
        res2 = self.nodes[0].eth_call(call_request, { "blockHash": block_a })
        assert_equal(res1, res2)

        res1 = self.nodes[0].eth_call(call_request, epoch_e)
        res2 = self.nodes[0].eth_call(call_request, { "blockHash": block_e })
        assert_equal(res1, res2)

        # should reject nonexistent block
        assert_raises_rpc_error(None, None, self.nodes[0].eth_call, call_request, { "blockHash": "0x0123456789012345678901234567890123456789012345678901234567890123" })

        # should reject non-pivot block
        assert_raises_rpc_error(None, None, self.nodes[0].eth_call, call_request, { "blockHash": block_d })

        self.log.info("Pass")

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

if __name__ == "__main__":
    CrossSpaceLogFilteringTest().main()
