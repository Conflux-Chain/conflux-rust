#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys, random, time, json
from typing import Tuple
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from eth_utils import decode_hex
from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_is_hex_string, assert_raises_rpc_error, connect_nodes, sync_blocks, get_contract_instance, load_contract_metadata
from web3 import Web3

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

ERA_EPOCH_COUNT = 100
NUM_BLOCKS = 600
NUM_TXS = 10
BLAME_CHECK_OFFSET = 20

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
        # Disable 1559 for RPC tests temporarily
        self.conf_parameters["cip1559_transition_height"] = str(99999999)

    def deploy_contract(self, data_hex):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver="", data_hex=data_hex, storage_limit=2000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, contract, data_hex, value=0):
        tx = self.rpc[FULLNODE0].new_contract_tx(receiver=contract, data_hex=data_hex, value=value, storage_limit=2000)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc[FULLNODE0].get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x0")
        return receipt

    def _setup_stake_contract(self, addr, priv):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(file_dir, "../..", "internal_contract", "metadata", "Staking.json")
        staking_contract_dict = json.loads(open(os.path.join(file_path), "r").read())
        staking_contract = get_contract_instance(contract_dict=staking_contract_dict)
        contract_addr = Web3.to_checksum_address("0888000000000000000000000000000000000002")
        tx_conf = {
            "from": Web3.to_checksum_address(addr),
            "to": contract_addr,
            "nonce": 0,
            "gas": 3_000_000,
            "gasPrice": 1,
            "chainId": 0
        }

        tx_data = decode_hex(staking_contract.functions.deposit(10 ** 18).build_transaction(tx_conf)["data"])
        tx = self.rpc[FULLNODE0].new_tx(value=0, sender=addr, receiver=contract_addr, gas=3_000_000, data=tx_data, priv_key=priv)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())

        tx_data = decode_hex(staking_contract.functions.voteLock(4 * 10 ** 17, 100000).build_transaction(tx_conf)["data"])
        tx = self.rpc[FULLNODE0].new_tx(value=0, sender=addr, receiver=contract_addr, gas=3_000_000, data=tx_data, priv_key=priv)
        assert_equal(self.rpc[FULLNODE0].send_tx(tx, True), tx.hash_hex())

    def _setup_sponsor(self, contractAddr):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(file_dir, "../..", "internal_contract", "metadata", "SponsorWhitelistControl.json")
        contract_dict = json.loads(open(os.path.join(file_path), "r").read())
        whitelist_control = get_contract_instance(contract_dict=contract_dict)
        whitelist_control_addr = "0x0888000000000000000000000000000000000001"

        tx_conf = {
            "from": Web3.to_checksum_address(self.rpc[FULLNODE0].GENESIS_ADDR),
            "gas": 3_000_000,
            "gasPrice": 1,
            "chainId": 0,
        }

        # setSponsorForGas
        data = whitelist_control.functions.setSponsorForGas(Web3.to_checksum_address(contractAddr), 2000000).build_transaction({"to":Web3.to_checksum_address(whitelist_control_addr), **tx_conf})["data"]
        self.call_contract(contract=whitelist_control_addr, data_hex=data, value=20000000000000000000)

        # setSponsorForCollateral
        data = whitelist_control.functions.setSponsorForCollateral(Web3.to_checksum_address(contractAddr)).build_transaction({"to":Web3.to_checksum_address(whitelist_control_addr), **tx_conf})["data"]
        self.call_contract(contract=whitelist_control_addr, data_hex=data, value=20000000000000000000)

        # add to whitelist
        self.sponsored_address = "0x1637feaab9faa11bf809f37967c3c8a43b8b874d"
        self.call_contract(contractAddr, "0a3b0a4f0000000000000000000000001637feaab9faa11bf809f37967c3c8a43b8b874d")

    def _create_branch(self) -> Tuple[str, str]:
        client = self.rpc[FULLNODE0]
        start_nonce = client.get_nonce(client.GENESIS_ADDR)
        txs = [client.new_tx(receiver=client.rand_addr(), nonce = start_nonce + ii) for ii in range(NUM_TXS)]
        parent_hash = client.block_by_epoch("latest_mined")['hash']
        #                      ---        ---        ---
        #                  .- | A | <--- | C | <--- | D | <--- ...
        #           ---    |   ---        ---        ---
        # ... <--- | P | <-*                          .
        #           ---    |   ---                    .
        #                  .- | B | <..................
        #                      ---
        block_a = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
        block_b = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
        block_c = client.generate_custom_block(parent_hash = block_a, referee = [], txs = [])
        block_d = client.generate_custom_block(parent_hash = block_c, referee = [block_b], txs = txs)

        parent_hash = block_d
        for _ in range(5):
            block = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block
            
        return block_b, block_d

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [RpcClient()] * self.num_nodes
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
        block_b, block_d = self._create_branch()
        self.block_b = block_b
        self.block_d = block_d

        # deploy contract
        bytecode = load_contract_metadata("CommissionPrivilegeTest")["bytecode"]
        receipt, contractAddr = self.deploy_contract(bytecode)
        self.log.info(f"contract deployed: {contractAddr}")
        self._setup_sponsor(contractAddr)

        (self.stake_addr, self.stake_priv) = self.rpc[FULLNODE0].rand_account()
        tx = self.rpc[FULLNODE0].new_tx(receiver=self.stake_addr, value=10**19)
        self.rpc[FULLNODE0].send_tx(tx, wait_for_receipt=True)
        self._setup_stake_contract(self.stake_addr, self.stake_priv)

        self.user = self.rpc[FULLNODE0].GENESIS_ADDR
        self.contract = contractAddr
        self.deploy_tx = receipt['transactionHash']

        # make sure we can check the blame for each header
        self.rpc[FULLNODE0].generate_blocks(BLAME_CHECK_OFFSET)
        sync_blocks(self.nodes, sync_state=False)

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

        # `latestState` is not available on light nodes
        del full['latestState']
        del light['latestState']

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

        full = self.rpc[FULLNODE0].get_account(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_account(self.user, latest_state)
        assert_equal(light, full)

        full = self.rpc[FULLNODE0].get_account(self.contract, latest_state)
        light = self.rpc[LIGHTNODE].get_account(self.contract, latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getAccount")

        # --------------------------

        self.log.info(f"Checking cfx_getAccumulateInterestRate...")

        full = self.rpc[FULLNODE0].get_accumulate_interest_rate(latest_state)
        light = self.rpc[LIGHTNODE].get_accumulate_interest_rate(latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getAccumulateInterestRate")

        # --------------------------

        self.log.info(f"Checking cfx_getAdmin...")
        full = self.rpc[FULLNODE0].get_admin(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_admin(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getAdmin")

        # --------------------------

        self.log.info(f"Checking cfx_getBalance...")
        full = self.rpc[FULLNODE0].get_balance(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_balance(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getBalance")

        # --------------------------

        self.log.info(f"Checking cfx_getCode...")

        full = self.rpc[FULLNODE0].get_code(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_code(self.user, latest_state)
        assert_equal(light, full)

        full = self.rpc[FULLNODE0].get_code(self.contract, latest_state)
        light = self.rpc[LIGHTNODE].get_code(self.contract, latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getCode")

        # --------------------------

        self.log.info(f"Checking cfx_getCollateralForStorage...")
        full = self.rpc[FULLNODE0].get_collateral_for_storage(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_collateral_for_storage(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getCollateralForStorage")

        # --------------------------

        self.log.info(f"Checking cfx_getInterestRate...")

        full = self.rpc[FULLNODE0].get_interest_rate(latest_state)
        light = self.rpc[LIGHTNODE].get_interest_rate(latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getInterestRate")

        # --------------------------

        self.log.info(f"Checking cfx_getNextNonce...")
        full = self.rpc[FULLNODE0].get_nonce(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_nonce(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getNextNonce")

        # --------------------------

        self.log.info(f"Checking cfx_getSponsorInfo...")
        full = self.rpc[FULLNODE0].get_sponsor_info(self.contract, latest_state)
        light = self.rpc[LIGHTNODE].get_sponsor_info(self.contract, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getSponsorInfo")

        # --------------------------

        self.log.info(f"Checking cfx_getStakingBalance...")
        full = self.rpc[FULLNODE0].get_staking_balance(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_staking_balance(self.user, latest_state)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getStakingBalance")

        # --------------------------

        self.log.info(f"Checking cfx_getStorageAt...")

        full = self.rpc[FULLNODE0].get_storage_at(self.user, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        light = self.rpc[LIGHTNODE].get_storage_at(self.user, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        assert_equal(light, full)

        full = self.rpc[FULLNODE0].get_storage_at(self.contract, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        light = self.rpc[LIGHTNODE].get_storage_at(self.contract, "0x0000000000000000000000000000000000000000000000000000000000000000", latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getStorageAt")

        # --------------------------

        self.log.info(f"Checking cfx_getStorageRoot...")

        full = self.rpc[FULLNODE0].get_storage_root(self.user, latest_state)
        light = self.rpc[LIGHTNODE].get_storage_root(self.user, latest_state)
        assert_equal(light, full)

        full = self.rpc[FULLNODE0].get_storage_root(self.contract, latest_state)
        light = self.rpc[LIGHTNODE].get_storage_root(self.contract, latest_state)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getStorageRoot")

        # --------------------------

        self.log.info(f"Checking cfx_getDepositList & cfx_getVoteList")
        full = self.rpc[FULLNODE0].get_deposit_list(self.stake_addr, latest_state)
        light = self.rpc[LIGHTNODE].get_deposit_list(self.stake_addr, latest_state)
        assert full[0]["depositTime"].startswith("0x")
        assert_equal(light, full)

        full = self.rpc[FULLNODE0].get_vote_list(self.stake_addr, latest_state)
        light = self.rpc[LIGHTNODE].get_vote_list(self.stake_addr, latest_state)
        assert full[0]["unlockBlockNumber"].startswith("0x")
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_getDepositList & cfx_getVoteList")

        # --------------------------

        self.log.info(f"Checking cfx_checkBalanceAgainstTransaction")

        full = self.rpc[FULLNODE0].check_balance_against_transaction(account_addr=self.sponsored_address, contract_addr=self.contract, gas_limit=1, gas_price=1, storage_limit=1)
        light = self.rpc[LIGHTNODE].check_balance_against_transaction(account_addr=self.sponsored_address, contract_addr=self.contract, gas_limit=1, gas_price=1, storage_limit=1)
        assert_equal(light, full)

        self.log.info(f"Pass -- cfx_checkBalanceAgainstTransaction")

    def _test_single_rpc_methods_with_block_hash_param(self, rpc_call_name: str, params: list):
        self.log.info(f"Checking {rpc_call_name} with block hash parameter...")
        
        full = getattr(self.rpc[FULLNODE0], rpc_call_name)(*params, {
            "blockHash": self.block_d
        })
        rpc_call = getattr(self.rpc[LIGHTNODE], rpc_call_name)
        light = rpc_call(*params, {
            "blockHash": self.block_d
        })
        assert_equal(full, light)
        assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
            "blockHash": self.block_b
        })
        assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
            "blockHash": self.block_b,
            "requirePivot": True
        })

    # TODO: add tests for light nodes
    # current rpc supporting block hash
    # cfx_epochReceipts(not supported by light nodes)
    # RPC to support
    # cfx_getBalance
    # cfx_call
    def test_rpc_methods_with_block_hash_param(self):
        # --------------------------
        pairs = [
            ("get_code", [self.user]),
            ("get_nonce", [self.user]),
            ("get_balance", [self.user]),
            ("get_storage_at", [self.user, "0x0000000000000000000000000000000000000000000000000000000000000000"]),
            ("get_storage_at", [self.contract, "0x0000000000000000000000000000000000000000000000000000000000000000"]),
        ]
        for pair in pairs:
            self._test_single_rpc_methods_with_block_hash_param(pair[0], pair[1])

    def assert_blocks_equal(self, light_block, block):
        # light nodes do not retrieve receipts for block queries
        # so fields related to execution results are not filled

        # full nodes will use '0x0' for empty blocks and None
        # for transactions not executed yet
        block['gasUsed'] = None

        for tx in block['transactions']:
            if type(tx) is not dict: continue
            tx['blockHash'] = None
            tx['status'] = None
            tx['transactionIndex'] = None

        assert_equal(light_block, block)

    def test_block_methods(self):
        self.log.info(f"Generating blocks with transactions...")

        address = self.rpc[FULLNODE0].GENESIS_ADDR
        nonce = self.rpc[FULLNODE0].get_nonce(address)

        txs = []

        for ii in range(10):
            receiver = self.rpc[FULLNODE0].rand_addr()
            tx = self.rpc[FULLNODE0].new_tx(receiver=receiver, nonce=nonce + ii, gas_price=7)
            nonce += 1
            txs.append(tx)

        block_hash = self.rpc[FULLNODE0].generate_block_with_fake_txs(txs)

        # make sure txs are executed
        parent_hash = block_hash

        for _ in range(BLAME_CHECK_OFFSET + 10):
            parent_hash = self.rpc[FULLNODE0].generate_block_with_parent(parent_hash=parent_hash)

        sync_blocks(self.nodes, sync_state=False)
        time.sleep(1)

        # --------------------------

        self.log.info(f"Checking cfx_gasPrice...")

        light = self.rpc[LIGHTNODE].gas_price()

        # median of all (10) txs from the last 30 blocks
        # NOTE: full node samples more blocks so the result might be different
        assert_equal(light, 1)

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
        full = self.rpc[FULLNODE0].get_tx(self.deploy_tx)
        light = self.rpc[LIGHTNODE].get_tx(self.deploy_tx)
        self.assert_txs_equal(light, full)
        self.log.info(f"Pass -- cfx_getTransactionByHash")

        self.log.info(f"Checking cfx_getTransactionReceipt...")
        full = self.rpc[FULLNODE0].get_transaction_receipt(self.deploy_tx)
        light = self.rpc[LIGHTNODE].get_transaction_receipt(self.deploy_tx)
        assert_equal(light, full)
        self.log.info(f"Pass -- cfx_getTransactionReceipt")

        # note: cfx_getLogs and cfx_sendRawTransaction have separate tests

    def test_not_supported(self):
        self.log.info(f"Checking not supported APIs...")

        assert_raises_rpc_error(-32000, None, self.nodes[LIGHTNODE].cfx_call, {}, "latest_checkpoint")
        assert_raises_rpc_error(-32000, None, self.nodes[LIGHTNODE].cfx_estimateGasAndCollateral, {}, "latest_checkpoint")
        assert_raises_rpc_error(-32000, None, self.nodes[LIGHTNODE].cfx_getBlockByBlockNumber, "0x1", False)
        assert_raises_rpc_error(-32000, None, self.nodes[LIGHTNODE].cfx_getBlockRewardInfo, "latest_checkpoint")
        assert_raises_rpc_error(-32000, None, self.nodes[LIGHTNODE].cfx_getEpochReceipts, "latest_checkpoint")
        assert_raises_rpc_error(-32000, None, self.nodes[LIGHTNODE].cfx_getSupplyInfo, "latest_checkpoint")

        self.log.info(f"Pass -- not supported APIs")

    def run_test(self):
        self.test_local_methods()
        self.test_state_methods()
        self.test_block_methods()
        self.test_rpc_methods_with_block_hash_param()
        self.test_tx_methods()
        self.test_not_supported()

if __name__ == "__main__":
    LightRPCTest().main()
