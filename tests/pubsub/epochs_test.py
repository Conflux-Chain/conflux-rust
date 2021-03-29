#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import asyncio

from conflux.rpc import RpcClient
from conflux.pubsub import PubSubClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, connect_nodes

FULLNODE0 = 0
FULLNODE1 = 1
LIGHTNODE = 2

NUM_FORKS = 5
PREFIX_LEN = 10
SHORT_FORK_LEN = 20
LONG_FORK_LEN = 30

def flatten(l):
    return [item for sublist in l for item in sublist]

class PubSubTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.conf_parameters["enable_optimistic_execution"] = "false"

    def setup_network(self):
        self.add_nodes(self.num_nodes)

        self.start_node(FULLNODE0, ["--archive"])
        self.start_node(FULLNODE1, ["--archive"])
        self.start_node(LIGHTNODE, ["--light"], phase_to_wait=None)

        # set up RPC clients
        self.rpc = [None] * self.num_nodes
        self.rpc[FULLNODE0] = RpcClient(self.nodes[FULLNODE0])
        self.rpc[FULLNODE1] = RpcClient(self.nodes[FULLNODE1])
        self.rpc[LIGHTNODE] = RpcClient(self.nodes[LIGHTNODE])

        # set up PubSub clients
        self.pubsub = [None] * self.num_nodes
        self.pubsub[FULLNODE0] = PubSubClient(self.nodes[FULLNODE0])
        self.pubsub[FULLNODE1] = PubSubClient(self.nodes[FULLNODE1])
        self.pubsub[LIGHTNODE] = PubSubClient(self.nodes[LIGHTNODE])

        # connect nodes
        connect_nodes(self.nodes, FULLNODE0, FULLNODE1)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE0)
        connect_nodes(self.nodes, LIGHTNODE, FULLNODE1)

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])
        self.nodes[FULLNODE1].wait_for_phase(["NormalSyncPhase"])

    async def test_forks(self):
        # Generate a chain with multiple forks like this:
        # 1 -- 2 -- 3 -- 4
        #       \-- 3 -- 4 -- 5 -- 6
        #                 \-- 5 -- 6 -- 7 -- 8
        # we expect to see: 1, 2, 3, 4, 3, 4, 5, 6, 5, 6, 7, 8, ...

        # Subscription results are of the format:
        # {'epochHashesOrdered': ['0x6fbbcb69c3f2247dc8bc756648a55f324afb30236c0ecaaf477cbea3b00de6dc'], 'epochNumber': '0x8'}

        # subscribe
        sub_full = await self.pubsub[FULLNODE1].subscribe("epochs")
        sub_light = await self.pubsub[LIGHTNODE].subscribe("epochs")

        # genesis hash
        root_hash = self.nodes[FULLNODE0].best_block_hash()
        root_epoch = 0

        for ii in range(NUM_FORKS):
            self.log.info(f"[{ii}] Root: {root_hash[:10]}... (epoch {root_epoch})")

            # ---------------------------------------------
            # generate shared prefix of length `PREFIX_LEN`
            generated = self.generate_chain(root_hash, PREFIX_LEN)

            # collect results from subscription
            epochs = [e async for e in sub_full.iter()]
            assert_equal(epochs, [e async for e in sub_light.iter()])

            # check hashes
            hashes = flatten([e["epochHashesOrdered"] for e in epochs])
            assert_equal(hashes, generated)

            # check epoch numbers
            epoch_nums = [int(e["epochNumber"], 16) for e in epochs]
            assert_equal(epoch_nums, list(range(root_epoch + 1, root_epoch + 1 + PREFIX_LEN)))

            fork_hash = hashes[-1]
            fork_epoch = epoch_nums[-1]

            self.log.info(f"[{ii}] Forking at: {fork_hash[:10]}... (epoch {fork_epoch})")

            # ----------------------------------------
            # generate fork of length `SHORT_FORK_LEN`
            generated = self.generate_chain(fork_hash, SHORT_FORK_LEN)

            # collect results from subscription
            epochs = [e async for e in sub_full.iter()]
            assert_equal(epochs, [e async for e in sub_light.iter()])

            # check hashes
            hashes = flatten([e["epochHashesOrdered"] for e in epochs])
            assert_equal(hashes, generated)

            # check epoch numbers
            epoch_nums = [int(e["epochNumber"], 16) for e in epochs]
            assert_equal(epoch_nums, list(range(fork_epoch + 1, fork_epoch + 1 + SHORT_FORK_LEN)))

            # ----------------------------------------
            # generate fork of length `LONG_FORK_LEN`
            generated = self.generate_chain(fork_hash, LONG_FORK_LEN)

            # collect results from subscription
            epochs = [e async for e in sub_full.iter()]
            assert_equal(epochs, [e async for e in sub_light.iter()])

            # check hashes
            hashes = flatten([e["epochHashesOrdered"] for e in epochs])
            assert_equal(hashes, generated)

            # check epoch numbers
            epoch_nums = [int(e["epochNumber"], 16) for e in epochs]
            assert_equal(epoch_nums, list(range(fork_epoch + 1, fork_epoch + 1 + LONG_FORK_LEN)))

            # in the next iteration, we continue with the longer fork
            root_epoch = epoch_nums[-1]
            root_hash = hashes[-1]

            self.log.info(f"[{ii}] Pass")

        self.log.info(f"Pass -- forks")

    async def test_latest_state(self):
        parent = self.nodes[FULLNODE0].best_block_hash()

        sub_mined = await self.pubsub[FULLNODE0].subscribe("epochs", "latest_mined")
        sub_exec = await self.pubsub[FULLNODE0].subscribe("epochs", "latest_state")

        for _ in range(4):
            parent = self.rpc[FULLNODE0].generate_block_with_parent(parent)
            epoch = self.rpc[FULLNODE0].block_by_hash(parent)["height"]

            msg = await sub_mined.next()
            assert_equal(msg['epochNumber'], epoch)

            # epoch received not executed yet, should timeout
            try:
                # do not use an overly large timeout here;
                # if an epoch is not executed for 100s, this violates our
                # asssumptions and the node will return invalid results.
                msg = await sub_exec.next(timeout=2)
                assert(False)
            except:
                pass

        for _ in range(20):
            parent = self.rpc[FULLNODE0].generate_block_with_parent(parent)
            epoch = self.rpc[FULLNODE0].block_by_hash(parent)["height"]

            msg = await sub_mined.next()
            assert_equal(msg['epochNumber'], epoch)

            msg = await sub_exec.next()
            assert_equal(msg['epochNumber'], hex(int(epoch, 0) - 4))

        self.log.info(f"Pass -- latest_state")

    def run_test(self):
        assert(SHORT_FORK_LEN < LONG_FORK_LEN)
        asyncio.get_event_loop().run_until_complete(self.test_forks())
        asyncio.get_event_loop().run_until_complete(self.test_latest_state())

    def generate_chain(self, parent, len):
        hashes = [parent]
        for _ in range(len):
            hash = self.rpc[FULLNODE0].generate_block_with_parent(hashes[-1])
            hashes.append(hash)
        return hashes[1:]

if __name__ == "__main__":
    PubSubTest().main()
