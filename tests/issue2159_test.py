#!/usr/bin/env python3

import asyncio
import websockets

from conflux.rpc import RpcClient
from jsonrpcclient.clients.websockets_client import WebSocketsClient
from jsonrpcclient.exceptions import ReceivedErrorResponseError
from jsonrpcclient.requests import Request
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import pubsub_url

FULLNODE = 0

def block_on(op):
    return asyncio.get_event_loop().run_until_complete(op)

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

        # set up RPC over WS
        url = pubsub_url(node.index, node.rpchost, node.pubsubport)
        self.ws = WebSocketsClient(block_on(websockets.connect(url)))

        # wait for phase changes to complete
        self.nodes[FULLNODE].wait_for_phase(["NormalSyncPhase"])

    def run_test(self):
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
            resp = block_on(self.ws.send(Request("cfx_getEpochReceipts", epoch)))
            assert False, "cfx_getEpochReceipts request should have failed"
        except ReceivedErrorResponseError as e:
            self.log.info(e.response)
            assert e.response.data.startswith("\"Oversized payload")
        except Exception as e:
            assert False, f"unexpected error: {e}"

        # this should succeed
        # resp = self.rpc.node.cfx_getEpochReceipts(epoch)

        self.log.info("Pass")

if __name__ == "__main__":
    Issue2159Test().main()
