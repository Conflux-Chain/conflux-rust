#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, random, time
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_is_hex_string, assert_raises_rpc_error, connect_nodes, sync_blocks

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

ERA_EPOCH_COUNT = 100
NUM_BLOCKS = 600
NUM_TXS = 10
BLAME_CHECK_OFFSET = 20
CONTRACT_PATH = "../contracts/simple_storage.dat"

class LightRPCTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

        # set era and snapshot length
        self.conf_parameters["era_epoch_count"] = str(ERA_EPOCH_COUNT)
        self.conf_parameters["dev_snapshot_epoch_count"] = str(ERA_EPOCH_COUNT // 2)

        # set other params so that nodes won't crash
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["anticone_penalty_ratio"] = "10"
        self.conf_parameters["generate_tx_period_us"] = "100000"
        self.conf_parameters["timer_chain_beta"] = "20"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["block_cache_gc_period_ms"] = "10"

    def deploy_contract(self, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, storage_limit=1000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])
        self.rpc[LIGHTNODE] = RpcClient(self.nodes[LIGHTNODE])

        # connect nodes, wait for phase changes to complete
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

        # generate some blocks in advance
        self.log.info(f"Generating blocks...")
        self.rpc[FULLNODE0].generate_blocks(NUM_BLOCKS)

        # generate some transactions from the genesis address
        self.log.info(f"Generating transactions...")

        # send some txs to increase the nonce
        for nonce in range(0, NUM_TXS):
            receiver = self.rpc[FULLNODE0].rand_addr()
            tx = self.rpc[FULLNODE0].new_tx(receiver=receiver, nonce=nonce)
            self.rpc[FULLNODE0].send_tx(tx, wait_for_receipt=True)

        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()
        receipt, contractAddr = self.deploy_contract(bytecode)
        self.log.info(f"contract deployed: {contractAddr}")

        self.user = self.rpc[FULLNODE0].GENESIS_ADDR
        self.contract = contractAddr
        self.deploy_tx = receipt['transactionHash']

        # make sure we can check the blame for each header
        self.rpc[FULLNODE0].generate_blocks(BLAME_CHECK_OFFSET)
        sync_blocks(self.nodes)

        # save genesis hash
        self.GENESIS_HASH = self.nodes[FULLNODE0].cfx_getBlocksByEpoch("earliest")[-1]

    def test_local_methods(self):
        self.log.info(f"Checking cfx_getBestBlockHash...")
        full = self.nodes[FULLNODE0].cfx_getBestBlockHash()
        light = self.nodes[LIGHTNODE].cfx_getBestBlockHash()
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getBestBlockHash")

        # --------------------------

        self.log.info(f"Checking cfx_getBlocksByEpoch...")

        full = self.nodes[FULLNODE0].cfx_getBlocksByEpoch("earliest")
        light = self.nodes[LIGHTNODE].cfx_getBlocksByEpoch("earliest")
        assert_equal(light, full)

        full = self.nodes[FULLNODE0].cfx_getBlocksByEpoch("latest_checkpoint")
        light = self.nodes[LIGHTNODE].cfx_getBlocksByEpoch("latest_checkpoint")
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getBlocksByEpoch")

        # --------------------------

        self.log.info(f"Checking cfx_getConfirmationRiskByHash...")

        best = self.nodes[FULLNODE0].cfx_getBestBlockHash()
        full = self.nodes[FULLNODE0].cfx_getConfirmationRiskByHash(best)
        light = self.nodes[LIGHTNODE].cfx_getConfirmationRiskByHash(best)
        assert_equal(light, full)

        checkpoint = self.rpc[FULLNODE0].block_by_epoch("latest_checkpoint", True)['hash']
        full = self.nodes[FULLNODE0].cfx_getConfirmationRiskByHash(checkpoint)
        light = self.nodes[LIGHTNODE].cfx_getConfirmationRiskByHash(checkpoint)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getConfirmationRiskByHash")

        # --------------------------

        self.log.info(f"Checking cfx_clientVersion...")
        full = self.nodes[FULLNODE0].cfx_clientVersion()
        light = self.nodes[LIGHTNODE].cfx_clientVersion()
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_clientVersion")

        # --------------------------

        self.log.info(f"Checking cfx_epochNumber...")

        light = self.rpc[LIGHTNODE].epoch_number("earliest")
        assert_equal(light, 0)

        full = self.rpc[FULLNODE0].epoch_number("latest_checkpoint")
        light = self.rpc[LIGHTNODE].epoch_number("latest_checkpoint")
        assert_greater_than(light, 0) # make sure it's a meaningful test
        assert_equal(light, full)

        # TODO(thegaram): check why latest_confirmed is not the same on light and full nodes
        light = self.rpc[LIGHTNODE].epoch_number("latest_confirmed")
        assert_greater_than(light, 0)

        full = self.rpc[FULLNODE0].epoch_number("latest_mined")
        light = self.rpc[LIGHTNODE].epoch_number("latest_state")
        assert_equal(light, full - BLAME_CHECK_OFFSET)

        light = self.rpc[LIGHTNODE].epoch_number("latest_mined")
        assert_equal(light, full - BLAME_CHECK_OFFSET)

        assert_raises_rpc_error(None, None, self.rpc[LIGHTNODE].epoch_number, hex(full + BLAME_CHECK_OFFSET))

        self.log.info(f"Pass -- cfx_epochNumber")

        # --------------------------

        self.log.info(f"Checking cfx_getStatus...")
        full = self.nodes[FULLNODE0].cfx_getStatus()
        light = self.nodes[LIGHTNODE].cfx_getStatus()
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getStatus")

        # --------------------------

        self.log.info(f"Checking cfx_getSkippedBlocksByEpoch...")
        full = self.nodes[FULLNODE0].cfx_getSkippedBlocksByEpoch("latest_checkpoint")
        light = self.nodes[LIGHTNODE].cfx_getSkippedBlocksByEpoch("latest_checkpoint")
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getSkippedBlocksByEpoch")

    def test_state_methods(self):
        latest_state = self.nodes[LIGHTNODE].cfx_epochNumber("latest_state")

        # --------------------------

        self.log.info(f"Checking cfx_getAccount...")

        full = self.nodes[FULLNODE0].cfx_getAccount(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getAccount(self.user, latest_state)
        assert_equal(light, full)

        full = self.nodes[FULLNODE0].cfx_getAccount(self.contract, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getAccount(self.contract, latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getAccount")

        # --------------------------

        self.log.info(f"Checking cfx_getAccumulateInterestRate...")

        full = self.nodes[FULLNODE0].cfx_getAccumulateInterestRate(latest_state)
        light = self.nodes[LIGHTNODE].cfx_getAccumulateInterestRate(latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getAccumulateInterestRate")

        # --------------------------

        self.log.info(f"Checking cfx_getAdmin...")
        full = self.nodes[FULLNODE0].cfx_getAdmin(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getAdmin(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getAdmin")

        # --------------------------

        self.log.info(f"Checking cfx_getBalance...")
        full = self.nodes[FULLNODE0].cfx_getBalance(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getBalance(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getBalance")

        # --------------------------

        self.log.info(f"Checking cfx_getCode...")

        full = self.nodes[FULLNODE0].cfx_getCode(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getCode(self.user, latest_state)
        assert_equal(light, full)

        full = self.nodes[FULLNODE0].cfx_getCode(self.contract, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getCode(self.contract, latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getCode")

        # --------------------------

        self.log.info(f"Checking cfx_getCollateralForStorage...")
        full = self.nodes[FULLNODE0].cfx_getCollateralForStorage(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getCollateralForStorage(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getCollateralForStorage")

        # --------------------------

        self.log.info(f"Checking cfx_getInterestRate...")

        full = self.nodes[FULLNODE0].cfx_getInterestRate(latest_state)
        light = self.nodes[LIGHTNODE].cfx_getInterestRate(latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getInterestRate")

        # --------------------------

        self.log.info(f"Checking cfx_getNextNonce...")
        full = self.nodes[FULLNODE0].cfx_getNextNonce(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getNextNonce(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getNextNonce")

        # --------------------------

        self.log.info(f"Checking cfx_getSponsorInfo...")
        full = self.nodes[FULLNODE0].cfx_getSponsorInfo(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getSponsorInfo(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getSponsorInfo")

        # --------------------------

        self.log.info(f"Checking cfx_getStakingBalance...")
        full = self.nodes[FULLNODE0].cfx_getStakingBalance(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getStakingBalance(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getStakingBalance")

        # --------------------------

        self.log.info(f"Checking cfx_getStorageAt...")

        full = self.nodes[FULLNODE0].cfx_getStorageAt(self.user, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        light = self.nodes[LIGHTNODE].cfx_getStorageAt(self.user, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        assert_equal(light, full)

        full = self.nodes[FULLNODE0].cfx_getStorageAt(self.contract, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        light = self.nodes[LIGHTNODE].cfx_getStorageAt(self.contract, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getStorageAt")

        # --------------------------

        self.log.info(f"Checking cfx_getStorageRoot...")

        full = self.nodes[FULLNODE0].cfx_getStorageRoot(self.user, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getStorageRoot(self.user, latest_state)
        assert_equal(light, full)

        full = self.nodes[FULLNODE0].cfx_getStorageRoot(self.contract, latest_state)
        light = self.nodes[LIGHTNODE].cfx_getStorageRoot(self.contract, latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getStorageRoot")

    def assert_blocks_equal(self, light_block, block):
        # light nodes do not retrieve receipts for block queries
        # so fields related to execution results are not filled

        # full nodes will use '0x0' for empty blocks and None
        # for transactions not executed yet
        block['gasUsed'] = '0x0' if block['gasUsed'] == '0x0' else None

        for tx in block['transactions']:
            if type(tx) is not dict: continue
            tx['blockHash'] = None
            tx['status'] = None
            tx['transactionIndex'] = None

        assert_equal(light_block, block)

    def test_block_methods(self):
        self.log.info(f"Generating blocks with transactions...")

        address = self.rpc[FULLNODE0].GENESIS_ADDR
        nonce = int(self.nodes[FULLNODE0].cfx_getNextNonce(address), 16)

        txs = []

        for ii in range(10):
            receiver = self.rpc[FULLNODE0].rand_addr()
            tx = self.rpc[FULLNODE0].new_tx(receiver=receiver, nonce=nonce + ii, gas_price=7)
            nonce += 1
            txs.append(tx)

        block_hash = self.rpc[FULLNODE0].generate_block_with_fake_txs(txs)
        self.rpc[FULLNODE0].generate_blocks(BLAME_CHECK_OFFSET) # make sure txs are executed
        sync_blocks(self.nodes)

        # --------------------------

        self.log.info(f"Checking cfx_gasPrice...")

        light = self.nodes[LIGHTNODE].cfx_gasPrice()

        # median of all (10) txs from the last 30 blocks
        # NOTE: full node samples more blocks so the result might be different
        assert_equal(light, '0x1')

        self.log.info(f"Pass -- cfx_gasPrice")

        # --------------------------

        self.log.info(f"Checking cfx_getBlockByHash...")

        block = self.rpc[FULLNODE0].block_by_hash(self.GENESIS_HASH, True)
        light_block = self.rpc[LIGHTNODE].block_by_hash(self.GENESIS_HASH, True)
        self.assert_blocks_equal(light_block, block)

        block = self.rpc[FULLNODE0].block_by_hash(block_hash, False)
        light_block = self.rpc[LIGHTNODE].block_by_hash(block_hash, False)
        self.assert_blocks_equal(light_block, block)

        block = self.rpc[FULLNODE0].block_by_hash(block_hash, True)
        light_block = self.rpc[LIGHTNODE].block_by_hash(block_hash, True)
        self.assert_blocks_equal(light_block, block)

        block_1_epoch = block['height']
        block_1_hash = block['hash']

        self.log.info(f"Pass -- cfx_GetBlockByHash")

        # --------------------------

        self.log.info(f"Checking cfx_getBlockByEpochNumber...")

        block = self.rpc[FULLNODE0].block_by_epoch("earliest", True)
        light_block = self.rpc[LIGHTNODE].block_by_epoch("earliest", True)
        self.assert_blocks_equal(light_block, block)

        block = self.rpc[FULLNODE0].block_by_epoch(block_1_epoch, False)
        light_block = self.rpc[LIGHTNODE].block_by_epoch(block_1_epoch, False)
        self.assert_blocks_equal(light_block, block)

        block = self.rpc[FULLNODE0].block_by_epoch(block_1_epoch, True)
        light_block = self.rpc[LIGHTNODE].block_by_epoch(block_1_epoch, True)
        self.assert_blocks_equal(light_block, block)

        # NOTE: do not use "latest_state" or "latest_mined" as these
        # will point to different epochs on full and light nodes

        block = self.rpc[FULLNODE0].block_by_epoch("latest_checkpoint", False)
        light_block = self.rpc[LIGHTNODE].block_by_epoch("latest_checkpoint", False)
        self.assert_blocks_equal(light_block, block)

        block = self.rpc[FULLNODE0].block_by_epoch("latest_checkpoint", True)
        light_block = self.rpc[LIGHTNODE].block_by_epoch("latest_checkpoint", True)
        self.assert_blocks_equal(light_block, block)

        block_2_epoch = block['height']
        block_2_hash = block['hash']

        self.log.info(f"Pass -- cfx_getBlockByEpochNumber")

        # --------------------------

        self.log.info(f"Checking cfx_getBlockByHashWithPivotAssumption...")

        # NOTE: do not use "latest_state" or "latest_mined" as these
        # will point to different epochs on full and light nodes

        block = self.nodes[FULLNODE0].cfx_getBlockByHashWithPivotAssumption(self.GENESIS_HASH, self.GENESIS_HASH, "0x0")
        light_block = self.nodes[LIGHTNODE].cfx_getBlockByHashWithPivotAssumption(self.GENESIS_HASH, self.GENESIS_HASH, "0x0")
        self.assert_blocks_equal(light_block, block)

        block = self.nodes[FULLNODE0].cfx_getBlockByHashWithPivotAssumption(block_1_hash, block_1_hash, block_1_epoch)
        light_block = self.nodes[LIGHTNODE].cfx_getBlockByHashWithPivotAssumption(block_1_hash, block_1_hash, block_1_epoch)
        self.assert_blocks_equal(light_block, block)

        block = self.nodes[FULLNODE0].cfx_getBlockByHashWithPivotAssumption(block_2_hash, block_2_hash, block_2_epoch)
        light_block = self.nodes[LIGHTNODE].cfx_getBlockByHashWithPivotAssumption(block_2_hash, block_2_hash, block_2_epoch)
        self.assert_blocks_equal(light_block, block)

        assert_raises_rpc_error(None, None, self.nodes[LIGHTNODE].cfx_getBlockByHashWithPivotAssumption, block_1_hash, block_2_hash, block_1_epoch)
        assert_raises_rpc_error(None, None, self.nodes[LIGHTNODE].cfx_getBlockByHashWithPivotAssumption, block_1_hash, block_1_hash, block_2_epoch)

        self.log.info(f"Pass -- cfx_getBlockByHashWithPivotAssumption")

    def assert_txs_equal(self, light_tx, tx):
        # light nodes do not retrieve receipts for tx queries
        # so fields related to execution results are not filled

        tx['blockHash'] = None
        tx['contractCreated'] = None
        tx['status'] = None
        tx['transactionIndex'] = None

        assert_equal(light_tx, tx)

    def test_tx_methods(self):
        self.log.info(f"Checking cfx_getTransactionByHash...")
        full = self.nodes[FULLNODE0].cfx_getTransactionByHash(self.deploy_tx)
        light = self.nodes[LIGHTNODE].cfx_getTransactionByHash(self.deploy_tx)
        self.assert_txs_equal(light, full)
        self.log.info(f"Pass -- cfx_getTransactionByHash")

        self.log.info(f"Checking cfx_getTransactionReceipt...")
        full = self.nodes[FULLNODE0].cfx_getTransactionReceipt(self.deploy_tx)
        light = self.nodes[LIGHTNODE].cfx_getTransactionReceipt(self.deploy_tx)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getTransactionReceipt")

        # note: cfx_getLogs and cfx_sendRawTransaction have separate tests

    def test_not_supported(self):
        self.log.info(f"Checking not supported APIs...")

        assert_raises_rpc_error(None, None, self.nodes[LIGHTNODE].cfx_call, {}, "latest_checkpoint")
        assert_raises_rpc_error(None, None, self.nodes[LIGHTNODE].cfx_checkBalanceAgainstTransaction, "0x1386b4185a223ef49592233b69291bbe5a80c527", "0x8b017126d2fede908a86b36b43969f17d25f3771", "0x5208", "0x2540be400", "0x0", "latest_checkpoint")
        assert_raises_rpc_error(None, None, self.nodes[LIGHTNODE].cfx_estimateGasAndCollateral, {}, "latest_checkpoint")
        assert_raises_rpc_error(None, None, self.nodes[LIGHTNODE].cfx_getBlockRewardInfo, "latest_checkpoint")

        self.log.info(f"Pass -- not supported APIs")

    def run_test(self):
        self.test_local_methods()
        self.test_state_methods()
        self.test_block_methods()
        self.test_tx_methods()
        self.test_not_supported()

if __name__ == "__main__":
    LightRPCTest().main()
