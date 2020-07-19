#!/usr/bin/env python3
from argparse import ArgumentParser
from http.client import CannotSendRequest

from eth_utils import decode_hex

from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import PoWGenerateThread
from test_framework.blocktools import create_transaction, create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


# Convert weight to integer
def process_chain(chain):
    for i in range(len(chain)):
        chain[i][1] = parse_as_int(chain[i][1])
    return chain


class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.start_attack = True
        self.rpc_timewait = 3600

    def add_options(self, parser:ArgumentParser):
        parser.add_argument(
            "--evil",
            dest="evil_rate",
            default=0.3,
            type=float,
        )

    def setup_chain(self):
        self.log.info("Initializing test directory " + self.options.tmpdir)
        self.total_period = 0.05
        self.evil_rate = self.options.evil_rate
        self.difficulty = 4  # default test difficulty
        self.conf_parameters = {
            "log_level": "\"debug\"",
            "headers_request_timeout_ms": "6000000",  # need to be larger than network latency
            "max_allowed_timeout_in_observing_period": "1000000000",
            "blocks_request_timeout_ms": "6000000",
            "heartbeat_timeout_ms": "1000000000",
            "max_inflight_request_count": "1000000"
        }
        self._initialize_chain_clean()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes, 0, 1)

        # Set latency between two groups
        self.nodes[0].addlatency(self.nodes[1].key, 400)
        self.nodes[1].addlatency(self.nodes[0].key, 400)

    def run_test(self):
        start_p2p_connection(self.nodes)

        honest_generation_period = self.total_period / (1-self.evil_rate) * 2
        PoWGenerateThread("node0", self.nodes[0], honest_generation_period * 1000, self.log).start()
        PoWGenerateThread("node1", self.nodes[1], honest_generation_period * 1000, self.log).start()

        evil_generation_period = 1/(1/self.total_period * self.evil_rate)
        self.log.info("Adversary mining average period=%f", evil_generation_period)

        # Find the fork point
        finished = False
        while not finished:
            chain0 = process_chain(self.nodes[0].getPivotChainAndWeight())
            chain1 = process_chain(self.nodes[1].getPivotChainAndWeight())
            fork_height = 0
            while True:
                if chain0[fork_height][0] != chain1[fork_height][0]:
                    fork0 = chain0[fork_height]
                    fork1 = chain1[fork_height]
                    self.log.info("Forked at height %d %s %s", fork_height, fork0, fork1)
                    finished = True
                    break
                fork_height += 1
                if fork_height >= min(len(chain0), len(chain1)):
                    self.log.info("No fork to start attack, retry")
                    time.sleep(0.1)
                    break
        if fork_height >= 5:
            # Our generated block has height fork_height+1, so its deferred block is fork_height-4
            receipts_root = decode_hex(self.nodes[0].getExecutedInfo(chain0[fork_height - 4][0])[0])
        else:
            receipts_root = default_config["GENESIS_RECEIPTS_ROOT"]

        merged = False
        start = time.time()
        total_sleep = 0
        while True:
            # This roughly determines adversary's mining power
            total_sleep += random.expovariate(1 / evil_generation_period)
            elapsed = time.time() - start
            if elapsed < total_sleep:
                time.sleep(total_sleep - elapsed)
            else:
                self.log.info(f"slow adversary {elapsed} {total_sleep}")

            fork0 = process_chain(self.nodes[0].getPivotChainAndWeight((fork_height, fork_height)))[0]
            adaptive0 = self.nodes[0].cfx_getBlockByEpochNumber("latest_mined", False)["adaptive"]
            fork1 = process_chain(self.nodes[1].getPivotChainAndWeight((fork_height, fork_height)))[0]
            adaptive1 = self.nodes[0].cfx_getBlockByEpochNumber("latest_mined", False)["adaptive"]
            self.log.info(f"Fork weights: {fork0} {fork1}")
            self.log.debug(f"two node adaptive: {adaptive0} {adaptive1}")
            if fork0[0] == fork1[0] and not merged:
                self.log.info("Pivot chain merged")
                merged = True
            if not adaptive0 and not adaptive1 and merged:
                self.log.info("adaptive blocks stopped")
                break
            ''' Send blocks to keep balance.
                The adversary's mining power and strategy is not strictly designed in the naive version.
                If two forks are already balanced, we need to send blocks to both sides in case no blocks are mined.
            '''
            if self.start_attack:
                if not merged:
                    if fork0[1] < fork1[1] or (fork0[1] == fork1[1] and fork0[0] < fork1[0]):
                        send1 = True
                    else:
                        send1 = False
                if send1:
                    parent = fork0[0]
                    block = NewBlock(create_block(decode_hex(parent), height=fork_height+1, deferred_receipts_root=receipts_root, difficulty=self.difficulty, timestamp=int(time.time()), author=decode_hex("%040x" % random.randint(0, 2**32 - 1))))
                    self.nodes[0].p2p.send_protocol_msg(block)
                    self.log.debug("send to 0 block %s, weight %d %d", block.block.hash_hex(), fork0[1], fork1[1])
                else:
                    parent = fork1[0]
                    block = NewBlock(create_block(decode_hex(parent), height=fork_height+1, deferred_receipts_root=receipts_root, difficulty=self.difficulty, timestamp=int(time.time()), author=decode_hex("%040x" % random.randint(0, 2**32 - 1))))
                    self.nodes[1].p2p.send_protocol_msg(block)
                    self.log.debug("send to 1 block %s, weight %d %d", block.block.hash_hex(), fork0[1], fork1[1])
        exit()



if __name__ == "__main__":
    P2PTest().main()
