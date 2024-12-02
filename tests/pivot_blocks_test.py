#!/usr/bin/env python3
from conflux.rpc import RpcClient
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, wait_for_initial_nonce_for_privkey, wait_for_account_stable
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

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

class PivotBlocksTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self._add_genesis_secrets(20)

    def setup_network(self):
        self.setup_nodes()


    def assert_pivot_chain_correct(self, start_hash: str=None):
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

            
    def gen_pivot_switch(self, tail_hash: str=None) -> tuple[Fork, Fork]:
        if tail_hash is None:
            best_block_hash = self.rpc.best_block_hash()
        else:
            best_block_hash = tail_hash
        fork1 = Fork(self.rpc, best_block_hash)
        fork2 = Fork(self.rpc, best_block_hash)
        fork1.grow_length(10)
        for num in range(9):
            
            fork2.grow_with_referee(fork1.chain[num+1], txs=[
                self.rpc.new_tx(
                    receiver=self.rpc.rand_addr(),
                    priv_key=self.core_secrets[num],
                )
            ])
        fork2.grow_length(1000)
        self.assert_pivot_chain_correct(fork2.tail_hash)
        fork1.grow_length(20)
        fork1.grow_with_referee(fork2.tail_hash)
        fork1.grow_length(20)
        self.assert_pivot_chain_correct(fork1.tail_hash)
        return fork1, fork2
        
        

    def run_test(self):
        self.rpc = RpcClient(self.nodes[0])
        
        blocks = self.rpc.generate_blocks(20)
        # time.sleep(5)
        # print latest epoch number
        print(f"latest epoch number: {self.rpc.epoch_number()}")
        self.assert_pivot_chain_correct(blocks[-1])
        fork1, fork2 = self.gen_pivot_switch(blocks[-6])

        
        self.assert_pivot_chain_correct()
        
        self.log.info("Pass")



if __name__ == "__main__":
    PivotBlocksTest().main()
