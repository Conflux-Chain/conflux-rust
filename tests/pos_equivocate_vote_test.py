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
        client = RpcClient(self.nodes[self.num_nodes - 1])
        wait_until(lambda: client.pos_status()["latestVoted"] is not None)
        print(client.pos_status())
        expected_round = int(client.pos_status()["latestVoted"], 0) + 1
        latest_round_blocks = set()
        while len(latest_round_blocks) <= 1:
            latest_round_blocks.clear()
            for b in client.pos_get_consensus_blocks():
                print(b["hash"], b["signatures"])
                if len(b["signatures"]) == 0:
                    self.log.info(str(b))
                round = int(b["round"], 0)
                if round == expected_round:
                    latest_round_blocks.add(b["hash"])
        for b in latest_round_blocks:
            self.log.info("force_vote %s", b)
            self.nodes[self.num_nodes - 1].pos_force_vote_proposal(b)
            # wait for the vote to be processed.
            time.sleep(0.2)
        time.sleep(60)
        client.pos_retire_self()

        time.sleep(120)
        print("balance before unstake", client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))))
        client.wait_for_unstake()
        print("balance after unstake", client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))))
        # assert (self.nodes[0].getblockcount() == 6002)

if __name__ == '__main__':
    PosEquivocateVoteTest().main()
