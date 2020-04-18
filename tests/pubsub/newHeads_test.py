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

NUM_BLOCKS = 100

class PubSubTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3

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

    async def run_async(self):
        # subscribe
        sub_full = await self.pubsub[FULLNODE1].subscribe("newHeads")
        sub_light = await self.pubsub[LIGHTNODE].subscribe("newHeads")

        # -------- 1. receive headers one-by-one --------
        for _ in range(NUM_BLOCKS):
            hash = self.rpc[FULLNODE0].generate_block()

            # check archive node pub-sub
            block = await sub_full.next()
            assert_equal(block["hash"], hash)

            # check light node pub-sub
            block = await sub_light.next()
            assert_equal(block["hash"], hash)

        self.log.info("Pass -- 1")

        # -------- 2. receive headers concurrently --------
        hashes = self.rpc[FULLNODE0].generate_blocks(NUM_BLOCKS)

        # NOTE: headers might be received out-of-order
        full_hashes = [h["hash"] async for h in sub_full.iter()]
        assert_equal(sorted(hashes), sorted(full_hashes))

        light_hashes = [h["hash"] async for h in sub_light.iter()]
        assert_equal(sorted(hashes), sorted(light_hashes))

        self.log.info("Pass -- 2")

        await sub_full.unsubscribe()
        await sub_light.unsubscribe()

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async())

if __name__ == "__main__":
    PubSubTest().main()
