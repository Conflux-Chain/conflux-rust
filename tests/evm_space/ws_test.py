#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

import asyncio
import websockets

from base import Web3Base
from jsonrpcclient import request_json, parse_json, Ok
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from test_framework.mininode import *
from test_framework.util import *

class EthWsTest(Web3Base):
    async def test_ws(self):
        url = "ws://%s:%d" % ("127.0.0.1", self.nodes[0].ethwsport)
        self.log.info(url)
        self.ws = await websockets.connect(url)

        # eth RPC works
        req = request_json("web3_clientVersion")
        await self.ws.send(req)
        resp = parse_json(await self.ws.recv())
        if isinstance(resp, Ok):
            self.log.info(resp.result)
        else:
            raise ReceivedErrorResponseError(resp)

        req = request_json("eth_blockNumber")
        await self.ws.send(req)
        resp = parse_json(await self.ws.recv())
        if isinstance(resp, Ok):
            self.log.info(resp.result)
        else:
            raise ReceivedErrorResponseError(resp)

        req = request_json("eth_getBlockByNumber", params=("latest", False))
        await self.ws.send(req)
        resp = parse_json(await self.ws.recv())
        if isinstance(resp, Ok):
            self.log.info(resp.result)
        else:
            raise ReceivedErrorResponseError(resp)

        # cfx RPC fails
        try:
            req = request_json("cfx_getStatus")
            await self.ws.send(req)
            resp = parse_json(await self.ws.recv())
            if isinstance(resp, Ok):
                self.log.info(resp.result)
            else:
                raise ReceivedErrorResponseError(resp)
        except ReceivedErrorResponseError:
            pass
        except Exception as e:
            raise AssertionError("Unexpected exception raised: " + type(e).__name__)

        self.log.info("Pass")

    def run_test(self):
        asyncio.run(self.test_ws())

if __name__ == "__main__":
    EthWsTest().main()
