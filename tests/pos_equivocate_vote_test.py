#!/usr/bin/env python3
"""An example functional test
"""
import eth_utils
import time

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import *


class PosEquivocateVoteTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'

    def run_test(self):
        time.sleep(10)
        client = RpcClient(self.nodes[self.num_nodes - 1])
        max_round = 0
        latest_round_blocks = set()
        while len(latest_round_blocks) <= 1:
            latest_round_blocks.clear()
            for b in client.pos_get_consensus_blocks():
                if len(b["signatures"]) == 0:
                    print(b)
                round = int(b["round"], 0)
                if round > max_round:
                    max_round = round
                    latest_round_blocks.clear()
                if round == max_round:
                    latest_round_blocks.add(b["hash"])
        for b in latest_round_blocks:
            self.nodes[self.num_nodes - 1].pos_force_vote_proposal(b)
        time.sleep(60)
        client.pos_retire_self()

        time.sleep(120)
        print("balance before unstake", client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))))
        client.wait_for_unstake()
        print("balance after unstake", client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))))
        exit()
        # assert (self.nodes[0].getblockcount() == 6002)

if __name__ == '__main__':
    PosEquivocateVoteTest().main()
