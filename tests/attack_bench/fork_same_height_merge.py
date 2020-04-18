#!/usr/bin/env python3
import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))


from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.block_gen_thread import BlockGenThread

'''
An attacker keeps mining with the same parent block and release them at once.
'''
class SameHeightTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        n_generate_batch = 1000
        n_initial_chain = 50000
        self.log.info(f"Prepare the initial chain of node 0 with {n_initial_chain} blocks")
        n_batches = int(n_initial_chain / n_generate_batch)
        for i in range(n_batches):
            batch_generate(self.nodes[0], n_generate_batch, self.log)
        n_fork_height = 1000
        n_star_count = 15000
        for i in range(self.num_nodes):
            self.log.info(f"Prepare node {i} with a chain of the length {n_fork_height} and then a star of {n_star_count} blocks.")
            client = RpcClient(self.nodes[i])
            fork_point = client.generate_empty_blocks(n_fork_height)[-1]
            for _ in range(n_star_count):
                client.generate_block_with_parent(fork_point)
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)
        self.log.info("Nodes connected, normal mining start at the interval of 0.5")
        block_gen_thread = BlockGenThread(self.nodes, self.log, interval_base=0.5)
        block_gen_thread.start()
        start_time = time.time()
        original_cnt = self.nodes[0].getblockcount()
        for _ in range(1000):
            time.sleep(1)
            cnt = self.nodes[0].getblockcount()
            elapsed = time.time() - start_time
            avg_block_processing = (cnt - original_cnt) / elapsed
            self.log.info(f"Node 0 block count {cnt}, elapsed {elapsed}, {avg_block_processing} blocks/s")

def batch_generate(node, n_blocks, log):
    start = time.time()
    node.generate_empty_blocks(n_blocks)
    elapsed = time.time() - start
    log.info(f"process {n_blocks} blocks with {elapsed} seconds")

if __name__ == '__main__':
    SameHeightTest().main()
