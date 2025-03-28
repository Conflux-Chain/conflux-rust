#!/usr/bin/env python3

import asyncio
import websockets

from conflux.rpc import RpcClient
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from jsonrpcclient import request_json, parse_json, Ok
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import pubsub_url

FULLNODE = 0

class Issue2159Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

        self.conf_parameters = {
            # make `cfx_getEpochReceipts` available through ws
            "public_rpc_apis": "\"cfx,debug\"",

            # limit max response payload size
            "jsonrpc_ws_max_payload_bytes": 1024,
        }

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(FULLNODE, ["--archive"])

        # set up RPC over HTTP
        node = self.nodes[FULLNODE]
        self.rpc = RpcClient(node)

        # wait for phase changes to complete
        self.nodes[FULLNODE].wait_for_phase(["NormalSyncPhase"])
        
    async def setup_ws(self):
        url = pubsub_url(self.nodes[FULLNODE].index, False, self.nodes[FULLNODE].rpchost, self.nodes[FULLNODE].pubsubport)
        self.ws = await websockets.connect(url)
        
    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.run_async_test())

    async def run_async_test(self):
        await self.setup_ws()
        # generate block with many transactions
        parent_hash = self.rpc.block_by_epoch("latest_mined")['hash']
        start_nonce = self.rpc.get_nonce(self.rpc.GENESIS_ADDR)
        txs = [self.rpc.new_tx(nonce = start_nonce + ii) for ii in range(0, 100)]
        hash = self.rpc.generate_custom_block(parent_hash = parent_hash, referee = [], txs = txs)
        epoch = self.rpc.block_by_hash(hash)["epochNumber"]

        # make sure block is executed
        self.rpc.generate_empty_blocks(5)

        # getting epoch receipts should result in error
        try:
            await self.ws.send(request_json("cfx_getEpochReceipts", params=(epoch,)))
            resp = parse_json(await self.ws.recv())
            if isinstance(resp, Ok):
                assert False, "cfx_getEpochReceipts request should have failed"
            else:
                self.log.info(resp)
                assert resp.data.startswith("\"Oversized payload")
        except Exception as e:
            assert False, f"unexpected error: {e}"

        # this should succeed
        # resp = self.rpc.node.cfx_getEpochReceipts(epoch)

        self.log.info("Pass")

if __name__ == "__main__":
    Issue2159Test().main()
