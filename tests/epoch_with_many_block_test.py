#!/usr/bin/env python3
import random
from conflux.rpc import RpcClient
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, wait_for_initial_nonce_for_privkey, wait_for_account_stable
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

# 54,000,000 / 21000 = 2571.4x
TX_PER_BLOCK = 2571
EXPECTED_EPOCH_VOLUME = 9
MIN_NATIVE_BASE_PRICE = 10
FORK_NUM = 3

LAST_DUPLICATE_RATE = 0

class Fork:
    def __init__(self, rpc: RpcClient, tail_hash: str):
        self.rpc = rpc
        self._tail_hash = tail_hash
        self.chain = [tail_hash]
        
    @property
    def tail_hash(self):
        return self._tail_hash
    
    @tail_hash.setter
    def tail_hash(self, tail_hash: str):
        self._tail_hash = tail_hash
        self.chain.append(tail_hash)
    
    def grow_length(self, n: int):
        for i in range(n):
            self.tail_hash = self.rpc.generate_custom_block(parent_hash=self.tail_hash, referee=[], txs=[])

    def grow_with_referee(self, referee: Union[str, list], txs: list=[]):
        if isinstance(referee, str):
            referee = [referee]
        self.tail_hash = self.rpc.generate_custom_block(parent_hash=self.tail_hash, referee=referee, txs=txs)
        
    def grow_with_txs(self, txs: list):
        self.tail_hash = self.rpc.generate_custom_block(parent_hash=self.tail_hash, referee=[], txs=txs)
        
    def grow_with_tx_list(self, txs: list):
        # select max to TX_PER_BLOCK txs from txs, then pop them from txs
        while len(txs) > 0:
            self.grow_with_txs(txs[:TX_PER_BLOCK])  # [1,2][:4] = [1,2]
            txs = txs[TX_PER_BLOCK:]  # [1,2][4:] = []

class EpochWithManyBlockTest(ConfluxTestFramework):
    # DAG structure:
    # ----| block |----| block |----| block |----| block |----| block |----| block |----| block |----| block |--
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    #   |                                                                |
    #    -| block |----| block |----| block |----| block |----| block |- 
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["min_native_base_price"] = MIN_NATIVE_BASE_PRICE
        self.conf_parameters["next_hardfork_transition_height"] = 1
        self.conf_parameters["next_hardfork_transition_number"] = 1
        block_per_fork = math.ceil((EXPECTED_EPOCH_VOLUME-1) / (FORK_NUM - 1))

        accounts_need = block_per_fork * TX_PER_BLOCK * FORK_NUM
        self._add_genesis_secrets(accounts_need - 1)  # 2571 initial accounts
        print(f"accounts_need: {accounts_need}")

    def setup_network(self):
        self.setup_nodes()
        
    # generate once
    def gen_local_tx_pool(self, secrets: List[str], nonce):
        txs = []
        for secret in secrets:
            txs.append(self.rpc.new_typed_tx(
                receiver=self.rpc.rand_addr(),
                priv_key=secret,
                max_fee_per_gas=10**12,  # 1000 GDrip, use high enough base fee
                epoch_height=0,
                nonce=nonce,
            ))
        return txs


    def assert_pivot_chain_correct(self, start_hash: Union[str, None]=None):
        if start_hash is None:
            # start from the latest executed block
            pivot_block_hash = self.rpc.best_block_hash()
        else:
            # start from the given hash
            pivot_block_hash = start_hash
            block = self.rpc.block_by_hash(pivot_block_hash)

            assert block["epochNumber"] == block["height"], f"block {pivot_block_hash} is not on pivot chain: epoch number {block['epochNumber']} != height {block['height']}"
        
        # ensure is executed
        for i in range(5):
            latest_executed_epoch = self.rpc.epoch_number("latest_state")
            pivot_block_hash = self.rpc.block_by_hash(pivot_block_hash)["parentHash"]
            if latest_executed_epoch > int(block["epochNumber"], 16):
                break
            
        while True:
            block = self.rpc.block_by_hash(pivot_block_hash)
            epoch_number = block["epochNumber"]
            epoch_blocks = self.rpc.block_hashes_by_epoch(epoch_number)
            if len(epoch_blocks) > 0:
                print(f"pivot block for epoch {int(epoch_number, 16)}: {pivot_block_hash}")
                print(f"epoch {int(epoch_number, 16)} blocks: {epoch_blocks}")
                assert_equal(epoch_blocks[-1], pivot_block_hash)
            if epoch_number == "0x0":
                break
            pivot_block_hash = block["parentHash"]

    
    # if will change duplicate rate, set from small to larger (due to nonce setting)
    def test_with_duplicate_rate(self, tail_hash: Union[str, None]=None, duplicate_rate: float=0.5, tx_nonce=0):
        global LAST_DUPLICATE_RATE
        if duplicate_rate < LAST_DUPLICATE_RATE:
            raise Exception(f"duplicate rate {duplicate_rate} is less than last duplicate rate {LAST_DUPLICATE_RATE}")
        LAST_DUPLICATE_RATE = duplicate_rate
        LAST_DUPLICATE_RATE = duplicate_rate

        if tail_hash is None:
            best_block_hash = self.rpc.best_block_hash()
        else:
            best_block_hash = tail_hash
        
        # forks
        forks: List[Fork] = []
        for i in range(FORK_NUM):
            forks.append(Fork(self.rpc, best_block_hash))

        block_per_fork = math.ceil((EXPECTED_EPOCH_VOLUME-1) / (FORK_NUM - 1))
        tx_list_volume = TX_PER_BLOCK*block_per_fork
        tx_list_volume_with_duplicate = int(tx_list_volume*duplicate_rate)
        self.log.info(f"tx_list_volume: {tx_list_volume}, tx_list_volume_with_duplicate: {tx_list_volume_with_duplicate}")
        self.log.info(f"start to generate shared tx list")
        shared_tx_list = self.gen_local_tx_pool(self.core_secrets[0:tx_list_volume_with_duplicate], nonce=tx_nonce)
            
        for index, fork in enumerate(forks):
            self.log.info("start to generate tx list")
            fork_tx_list = shared_tx_list + \
                self.gen_local_tx_pool(self.core_secrets[index*tx_list_volume:(index+1)*tx_list_volume-tx_list_volume_with_duplicate], nonce=tx_nonce)

        
            random.shuffle(fork_tx_list)
            fork.grow_with_tx_list(fork_tx_list)
        
        forks[0].grow_with_referee([fork.tail_hash for fork in forks[1:]])
        forks[0].grow_length(20)
            
        self.assert_pivot_chain_correct(forks[0].tail_hash)
        return forks

    def run_test(self):
        self.rpc = RpcClient(self.nodes[0])
        
        blocks = self.rpc.generate_blocks(20)
        # time.sleep(5)
        # print latest epoch number
        print(f"latest epoch number: {self.rpc.epoch_number()}")
        self.test_with_duplicate_rate(blocks[-6], 0.5, tx_nonce=0)
        blocks = self.rpc.generate_blocks(20)
        self.test_with_duplicate_rate(blocks[-6], 0.7, tx_nonce=1)
        
        self.log.info("Pass")



if __name__ == "__main__":
    EpochWithManyBlockTest().main()