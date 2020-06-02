#!/usr/bin/env python3
from argparse import ArgumentParser
from http.client import CannotSendRequest

from eth_utils import decode_hex

from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.blocktools import create_transaction, create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

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
        mining_sleep_us = 10000
        self.total_period = 0.25
        self.evil_rate = self.options.evil_rate
        self.difficulty = int(2 / (1/self.total_period) / (1-self.evil_rate) * 10**6/mining_sleep_us)
        print(self.difficulty)
        self.conf_parameters = {
            "start_mining": "true",
            "initial_difficulty": str(self.difficulty),
            "test_mining_sleep_us": f"{mining_sleep_us}",
            "mining_author": '"' + "0"*40 + '"',
            "log_level": "\"debug\"",
            # "headers_request_timeout_ms": "60000",  # need to be larger than network latency
            # "heavy_block_difficulty_ratio": "1000",  # parameter used in the original experiments
            # "adaptive_weight_beta": "3000",  # parameter used in the original experiments
            "max_allowed_timeout_in_observing_period": "1000000000",
            # "blocks_request_timeout_ms": "60000",
            "heartbeat_timeout_ms": "1000000000",
        }
        self._initialize_chain_clean()

    def setup_network(self):
        self.setup_nodes()
        connect_nodes(self.nodes, 0, 1)

        # Set latency between two groups
        self.nodes[0].addlatency(self.nodes[1].key, 10000)
        self.nodes[1].addlatency(self.nodes[0].key, 10000)

    def run_test(self):
        start_p2p_connection(self.nodes)

        # Some blocks may have been mined before we setup the latency,
        # so wait for the latency and find the fork point
        generation_period = 1/(1/self.total_period * self.evil_rate)
        self.log.info("Adversary mining average period=%f", generation_period)

        # Some blocks may have been mined before we setup the latency,
        # so wait for the latency and find the fork point
        finished = False
        while not finished:
            chain0 = self.process_chain(self.nodes[0].getPivotChainAndWeight())
            chain1 = self.process_chain(self.nodes[1].getPivotChainAndWeight())
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

        count = 0
        after_count = 0
        merged = False
        start = time.time()
        while True:
            # This roughly determines adversary's mining power
            should_sleep = random.expovariate(1 / generation_period)
            elapsed = time.time() - start
            if elapsed < should_sleep:
                time.sleep(should_sleep - elapsed)
            else:
                self.log.info(f"slow adversary {elapsed} {should_sleep}")
            start = time.time()

            chain0 = self.process_chain(self.nodes[0].getPivotChainAndWeight())
            self.check_chain_heavy(chain0, 0, fork_height)
            chain1 = self.process_chain(self.nodes[1].getPivotChainAndWeight())
            self.check_chain_heavy(chain1, 1, fork_height)
            assert_equal(chain0[0][0], chain1[0][0])
            fork0 = chain0[fork_height]
            fork1 = chain1[fork_height]
            self.log.debug("Fork root %s %s", chain0[fork_height], chain1[fork_height])
            if fork0[0] == fork1[0]:
                merged = True
                # self.log.info("Pivot chain merged")
                # self.log.info("chain0 %s", chain0)
                # self.log.info("chain1 %s", chain1)
                after_count += 1
                if after_count >= 12*3600 / generation_period:
                    self.log.info("Merged. Winner: %s Chain end with %s", fork0[0], chain0[min(len(chain0), len(chain1)) - 2][0])
                    break
                continue

            count += 1
            if count >= 12*3600 / generation_period:
                self.log.info("Not merged after 12h")
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

    # Convert weight to integer
    def process_chain(self, chain):
        for i in range(len(chain)):
            chain[i][1] = parse_as_int(chain[i][1])
        return chain

    def check_chain_heavy(self, chain, chain_id, fork_height):
        for i in range(fork_height+1, len(chain)-1):
            if chain[i][1] - chain[i+1][1] >= self.difficulty * 240:
                self.log.debug("chain %d is heavy at height %d %d %d", chain_id, i,  chain[i][1], chain[i+1][1])
                return
        if chain[-1][1] >= self.difficulty * 240:
            self.log.debug("chain %d is heavy at height %d %d %d", chain_id, i,  chain[i][1], chain[i+1][1])


if __name__ == "__main__":
    P2PTest().main()
