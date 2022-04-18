#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import asyncio
import websockets

from base import Web3Base
from jsonrpcclient.clients.websockets_client import WebSocketsClient
from jsonrpcclient.requests import Request
from test_framework.mininode import *
from test_framework.util import *

class EthWsTest(Web3Base):
    async def test_ws(self):
        url = "ws://%s:%d" % ("127.0.0.1", self.nodes[0].ethwsport)
        self.log.info(url)
        self.ws = WebSocketsClient(await websockets.connect(url))

        # eth RPC works
        req = Request("web3_clientVersion")
        resp = await self.ws.send(req)
        self.log.info(resp.data.result)

        req = Request("eth_blockNumber")
        resp = await self.ws.send(req)
        self.log.info(resp.data.result)

        req = Request("eth_getBlockByNumber", "latest", False)
        resp = await self.ws.send(req)
        self.log.info(resp.data.result)

        # cfx RPC fails
        try:
            req = Request("cfx_getStatus")
            resp = await self.ws.send(req)
            self.log.info(resp.data.result)
        except jsonrpcclient.exceptions.ReceivedErrorResponseError:
            pass
        except Exception as e:
            raise AssertionError("Unexpected exception raised: " + type(e).__name__)

        self.log.info("Pass")

    def run_test(self):
        asyncio.get_event_loop().run_until_complete(self.test_ws())

if __name__ == "__main__":
    EthWsTest().main()
