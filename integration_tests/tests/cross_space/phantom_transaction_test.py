import os
from conflux_web3 import Web3
import pytest
from integration_tests.conflux.rpc import RpcClient
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import assert_equal, assert_is_hex_string, assert_ne, load_contract_metadata
from eth_utils import decode_hex, encode_hex as encode_hex_0x

from integration_tests.test_framework.util.common import (
    encode_bytes20,
    encode_u256,
    number_to_topic,
)
from integration_tests.conflux.utils import sha3 as keccak
from integration_tests.conflux.config import default_config

@pytest.fixture(scope="module")
def framework_class():
    class PhantomTransactionTestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["chain_id"] = str(10)
            self.conf_parameters["evm_chain_id"] = str(11)
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])
            self.rpc = RpcClient(self.nodes[0])

    return PhantomTransactionTestEnv


def test_phantom_transaction(network):
    self = network
    # initialize Conflux account
    self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
    self.cfxAccount = self.rpc.GENESIS_ADDR
    print(f'Using Conflux account {self.cfxAccount}')

    # initialize EVM account
    self.evmAccount = self.ew3.eth.account.from_key("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    print(f'Using EVM account {self.evmAccount.address}')
    cross_space_transfer(self, self.evmAccount.address, 1 * 10 ** 18)
    assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(1 * 10 ** 18))

    # deploy Conflux space contract
    confluxContractAddr = deploy_conflux_space(network)
    print(f'Conflux contract: {confluxContractAddr}')

    # deploy EVM space contract
    evmContractAddr = deploy_evm_space(self)
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

    evm_next_nonce = self.ew3.eth.get_transaction_count(self.evmAccount.address)
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
        tx, hash = construct_evm_tx(self,receiver=evmContractAddr, data_hex=data_hex, nonce = evm_next_nonce)
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
        receipt = self.ew3.eth.wait_for_transaction_receipt(h)
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
        assert_equal(tx["transactionIndex"], hex(idx))

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

    # check index
    for block_receipts in receipts:
        for idx, receipt in enumerate(block_receipts):
            assert_equal(receipt["index"], hex(idx))


    # ---------------------------------------------------------------------

    # EVM perspective:
    # A: 5 txs (events: [12], [], [13], [], [13, 13])
    # B: 5 txs (events: [15], [], [16], [], [16, 16])
    # C: /
    # E: 10 txs (events: [22], [], [23], [], [23, 23], [25], [], [26], [], [26, 26])

    # block #A
    block = self.nodes[0].eth_getBlockByNumber(epoch_a, True)
    assert_equal(len(block["transactions"]), 5)

    block2 = self.nodes[0].eth_getBlockByHash(block_a, True)
    assert_equal(block2, block)

    count = int(self.nodes[0].eth_getBlockTransactionCountByNumber(epoch_a), 16)
    assert_equal(count, len(block["transactions"]))

    count = int(self.nodes[0].eth_getBlockTransactionCountByHash(block_a), 16)
    assert_equal(count, len(block["transactions"]))

    tx_hashes = self.nodes[0].eth_getBlockByNumber(epoch_a, False)["transactions"]
    assert_equal(len(tx_hashes), 5)

    for idx, tx in enumerate(block["transactions"]):
        # check returned hash
        assert_equal(tx["hash"], tx_hashes[idx])

        # check indexing
        assert_equal(tx["transactionIndex"], hex(idx))

        # check eth_getTransactionByHash
        assert_equal(tx, self.nodes[0].eth_getTransactionByHash(tx["hash"]))

    # TODO: check transaction details

    receipts = self.nodes[0].parity_getBlockReceipts(epoch_a)
    assert_equal(len(receipts), 5)

    receipts2 = self.nodes[0].parity_getBlockReceipts({ "blockHash": block_a })
    assert_equal(receipts2, receipts)

    receipts2 = self.nodes[0].parity_getBlockReceipts({ "blockHash": block_a, "requireCanonical": True })
    assert_equal(receipts2, receipts)

    receipts2 = self.nodes[0].parity_getBlockReceipts({ "blockHash": block_a, "requireCanonical": False })
    assert_equal(receipts2, receipts)

    logIndex = 0

    filter = { "fromBlock": epoch_a, "toBlock": epoch_a }
    logsFiltered = self.nodes[0].eth_getLogs(filter)
    assert_equal(len(logsFiltered), 4)

    for idx, receipt in enumerate(receipts):
        assert_equal(receipt["blockHash"], block_a)
        assert_equal(receipt["blockNumber"], epoch_a)
        assert_equal(receipt["contractAddress"], None)
        assert_equal(receipt["status"], "0x1")
        assert_equal(receipt["transactionHash"], tx_hashes[idx])
        assert_equal(receipt["transactionIndex"], hex(idx))

        # TODO: check logs bloom, cumulative gas used

        assert_equal(receipt, self.nodes[0].eth_getTransactionReceipt(receipt["transactionHash"]))

        for idx2, log in enumerate(receipt["logs"]):
            assert_equal(log["address"], evmContractAddr.lower())
            assert_equal(log["blockHash"], block_a)
            assert_equal(log["blockNumber"], epoch_a)
            assert_equal(log["transactionHash"], tx_hashes[idx])
            assert_equal(log["transactionIndex"], hex(idx))
            assert_equal(log["logIndex"], hex(logIndex))
            assert_equal(log["transactionLogIndex"], hex(idx2))
            assert_equal(log["removed"], False)
            assert_equal(log, logsFiltered[logIndex])
            logIndex += 1

    assert_equal(len(receipts[0]["logs"]), 1)
    assert_equal(receipts[0]["logs"][0]["data"], number_to_topic(12))

    assert_equal(len(receipts[1]["logs"]), 0)
    assert_equal(len(receipts[2]["logs"]), 1)
    assert_equal(receipts[2]["logs"][0]["data"], number_to_topic(13))

    assert_equal(len(receipts[3]["logs"]), 0)
    assert_equal(len(receipts[4]["logs"]), 2)
    assert_equal(receipts[4]["logs"][0]["data"], number_to_topic(13))
    assert_equal(receipts[4]["logs"][1]["data"], number_to_topic(13))

    # block #D
    block = self.nodes[0].eth_getBlockByHash(block_d, True)
    assert_equal(block, None)

    count = self.nodes[0].eth_getBlockTransactionCountByHash(block_d)
    assert_equal(count, None)

    # block #E
    block = self.nodes[0].eth_getBlockByNumber(epoch_e, True)
    assert_equal(len(block["transactions"]), 10)

    block2 = self.nodes[0].eth_getBlockByHash(block_e, True)
    assert_equal(block2, block)

    count = int(self.nodes[0].eth_getBlockTransactionCountByNumber(epoch_e), 16)
    assert_equal(count, len(block["transactions"]))

    count = int(self.nodes[0].eth_getBlockTransactionCountByHash(block_e), 16)
    assert_equal(count, len(block["transactions"]))

    tx_hashes = self.nodes[0].eth_getBlockByNumber(epoch_e, False)["transactions"]
    assert_equal(len(tx_hashes), 10)

    for idx, tx in enumerate(block["transactions"]):
        # check returned hash
        assert_equal(tx["hash"], tx_hashes[idx])

        # check indexing
        assert_equal(tx["transactionIndex"], hex(idx))

        # check eth_getTransactionByHash
        assert_equal(tx, self.nodes[0].eth_getTransactionByHash(tx["hash"]))

    receipts = self.nodes[0].parity_getBlockReceipts(epoch_e)
    assert_equal(len(receipts), 10)

    receipts2 = self.nodes[0].parity_getBlockReceipts({ "blockHash": block_e })
    assert_equal(receipts2, receipts)

    logIndex = 0

    filter = { "fromBlock": epoch_e, "toBlock": epoch_e }
    logsFiltered = self.nodes[0].eth_getLogs(filter)
    assert_equal(len(logsFiltered), 8)

    for idx, receipt in enumerate(receipts):
        assert_equal(receipt["blockHash"], block_e)
        assert_equal(receipt["blockNumber"], epoch_e)
        assert_equal(receipt["contractAddress"], None)
        assert_equal(receipt["status"], "0x1")
        assert_equal(receipt["transactionHash"], tx_hashes[idx])
        assert_equal(receipt["transactionIndex"], hex(idx))

        # TODO: check logs bloom, cumulative gas used

        assert_equal(receipt, self.nodes[0].eth_getTransactionReceipt(receipt["transactionHash"]))

        for idx2, log in enumerate(receipt["logs"]):
            assert_equal(log["address"], evmContractAddr.lower())
            assert_equal(log["blockHash"], block_e)
            assert_equal(log["blockNumber"], epoch_e)
            assert_equal(log["transactionHash"], tx_hashes[idx])
            assert_equal(log["transactionIndex"], hex(idx))
            assert_equal(log["logIndex"], hex(logIndex))
            assert_equal(log["transactionLogIndex"], hex(idx2))
            assert_equal(log["removed"], False)
            assert_equal(log, logsFiltered[logIndex])
            logIndex += 1

    assert_equal(len(receipts[0]["logs"]), 1)
    assert_equal(receipts[0]["logs"][0]["data"], number_to_topic(22))

    assert_equal(len(receipts[1]["logs"]), 0)
    assert_equal(len(receipts[2]["logs"]), 1)
    assert_equal(receipts[2]["logs"][0]["data"], number_to_topic(23))

    assert_equal(len(receipts[3]["logs"]), 0)
    assert_equal(len(receipts[4]["logs"]), 2)
    assert_equal(receipts[4]["logs"][0]["data"], number_to_topic(23))
    assert_equal(receipts[4]["logs"][0]["data"], number_to_topic(23))

    assert_equal(len(receipts[5]["logs"]), 1)
    assert_equal(receipts[5]["logs"][0]["data"], number_to_topic(25))

    assert_equal(len(receipts[6]["logs"]), 0)
    assert_equal(len(receipts[7]["logs"]), 1)
    assert_equal(receipts[7]["logs"][0]["data"], number_to_topic(26))

    assert_equal(len(receipts[8]["logs"]), 0)
    assert_equal(len(receipts[9]["logs"]), 2)
    assert_equal(receipts[9]["logs"][0]["data"], number_to_topic(26))
    assert_equal(receipts[9]["logs"][0]["data"], number_to_topic(26))

    # ---------------------------------------------------------------------

    # make sure pending transactions can be retrieved even before execution
    evm_next_nonce += 1

    signed = self.evmAccount.sign_transaction({
        "to": evmContractAddr,
        "value": 0,
        "gasPrice": 1,
        "gas": 150000,
        "nonce": evm_next_nonce,
        "chainId": 11,
        "data": "0x",
    })

    tx_hash = self.ew3.eth.send_raw_transaction(signed["raw_transaction"])
    tx = self.nodes[0].eth_getTransactionByHash(tx_hash.hex())
    assert_ne(tx, None)

    self.log.info("Pass")

def cross_space_transfer(network, to, value):
    to = to.replace('0x', '')

    tx = network.rpc.new_tx(
        value=value,
        receiver="0x0888000000000000000000000000000000000006",
        data=decode_hex(f"0xda8d5daf{to}000000000000000000000000"),
        nonce=network.rpc.get_nonce(network.cfxAccount),
        gas=1000000,
    )

    network.rpc.send_tx(tx, True)

def deploy_conflux_space(self):
    bytecode = load_contract_metadata("CrossSpaceEventTestConfluxSide")['bytecode']
    tx = self.rpc.new_contract_tx(receiver="", data_hex=bytecode, sender=self.cfxAccount, priv_key=self.cfxPrivkey, storage_limit=20000)
    assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
    receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
    assert_equal(receipt["outcomeStatus"], "0x0")
    addr = receipt["contractCreated"]
    assert_is_hex_string(addr)
    return addr

def deploy_evm_space(self):
    bytecode = load_contract_metadata("CrossSpaceEventTestEVMSide")['bytecode']

    nonce = self.ew3.eth.get_transaction_count(self.evmAccount.address)

    signed = self.evmAccount.sign_transaction({
        "to": None,
        "value": 0,
        "gasPrice": 1,
        "gas": 500000,
        "nonce": nonce,
        "chainId": 11,
        "data": bytecode,
    })

    tx_hash = signed["hash"]
    return_tx_hash = self.ew3.eth.send_raw_transaction(signed["raw_transaction"])
    assert_equal(tx_hash, return_tx_hash)

    self.rpc.generate_block(1)
    self.rpc.generate_blocks(20, 1)
    receipt = self.ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert_equal(receipt["status"], 1)
    addr = receipt["contractAddress"]
    return addr

def construct_evm_tx(self, receiver, data_hex, nonce):
    signed = self.evmAccount.sign_transaction({
        "to": receiver,
        "value": 0,
        "gasPrice": 1,
        "gas": 150000,
        "nonce": nonce,
        "chainId": 11,
        "data": data_hex,
    })

    tx = [nonce, 1, 150000, bytes.fromhex(receiver.replace('0x', '')), 0, bytes.fromhex(data_hex.replace('0x', '')), signed["v"], signed["r"], signed["s"]]
    return tx, signed["hash"]