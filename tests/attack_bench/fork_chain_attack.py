#!/usr/bin/env python3
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.utils import parse_as_int
from eth_utils import decode_hex
from conflux.messages import NewBlock
from test_framework.mininode import start_p2p_connection


from conflux.rpc import RpcClient
from test_framework.blocktools import make_genesis, create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


'''
An attacker mines a fork chain at a fixed point and release them at once.
'''
class ForkChainTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["log_level"] = '"info"'

    def run_test(self):
        start_p2p_connection(self.nodes)
        overall_generate_period_ms = 10
        report_progress_blocks = 100
        initial_chain_length = 20000

        # Attacker computation power ratio in the total power
        attacker_ratio = 0.4
        attacker_generate_period_ms = overall_generate_period_ms / attacker_ratio
        victim_generation_period_ms = overall_generate_period_ms / (1 - attacker_ratio)

        # attacker = self.nodes[0]
        victim = self.nodes[0]
        self.log.info(f"Generate initial {initial_chain_length} blocks")
        last_block = victim.generate_empty_blocks(initial_chain_length)[-1]
        last_height = parse_as_int(RpcClient(victim).block_by_hash(last_block)["height"])
        victim_handler = Victim("VICTIM", victim, victim_generation_period_ms, self.log, report_progress_blocks,
                                fixed_period=True)
        victim_handler.start()
        self.log.info("Victim started")
        attacker_handler = Attacker("ATTACKER", victim, attacker_generate_period_ms, self.log)
        attacker_handler.set_fork_point(last_block, last_height)
        attacker_handler.start()
        self.log.info("Attacker started")
        victim_handler.join()


class Victim(PoWGenerateThread):
    def generate_block(self):
        self.node.generate_empty_blocks(1)


class Attacker(PoWGenerateThread):
    def set_fork_point(self, fork_hash, height):
        self.parent_hash = decode_hex(fork_hash)
        self.height = height + 1

    def generate_block(self):
        # if not hasattr(self, "parent_hash"):
        #     self.parent_hash = make_genesis().hash_hex()
        # self.parent_hash = self.node.generate_block_with_parent(self.parent_hash)
        block = create_block(parent_hash=self.parent_hash, height=self.height)
        self.node.p2p.send_protocol_msg(NewBlock(block=block))
        self.parent_hash = block.hash
        self.height += 1

if __name__ == '__main__':
    ForkChainTest().main()
