#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

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
        self.conf_parameters["pos_round_per_term"] = '10'

    def run_test(self):
        client = RpcClient(self.nodes[self.num_nodes - 1])
        wait_until(lambda: client.pos_status()["latestVoted"] is not None)
        expected_round = int(client.pos_status()["latestVoted"], 0) + 1
        latest_round_blocks = set()
        while len(latest_round_blocks) <= 1:
            latest_round_blocks.clear()
            for b in client.pos_get_consensus_blocks():
                round = int(b["round"], 0)
                if round == expected_round:
                    latest_round_blocks.add(b["hash"])
        for b in latest_round_blocks:
            self.log.info("force_vote %s", b)
            self.nodes[self.num_nodes - 1].test_posForceVoteProposal(b)
            # wait for the vote to be processed.
            time.sleep(0.2)
        client.generate_empty_blocks(300)
        client.pos_retire_self(2000)

        for i in range(40):
            print(i)
            # Retire node 3 after 2 min.
            # Generate enough PoW block for PoS to progress
            client.generate_empty_blocks(60)
            # Leave some time for PoS to reach consensus
            time.sleep(3)
            b = client.generate_empty_blocks(1)[0]
            print(client.block_by_hash(b)["posReference"])

        self.log.info("balance before unstake %s", client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))))
        client.wait_for_unstake()
        self.log.info("balance after unstake %s", client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))))
        # assert (self.nodes[0].test_getBlockCount() == 6002)

if __name__ == '__main__':
    PosEquivocateVoteTest().main()
