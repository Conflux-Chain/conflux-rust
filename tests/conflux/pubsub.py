# import sys
# sys.path.append("..")

import asyncio
import json
import websockets

from jsonrpcclient import request_json, parse_json, Ok
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from test_framework.util import pubsub_url

class PubSubClient:
    def __init__(self, node, evm=False):
        self.buffer = {}
        self.nid = node.index
        self.url = pubsub_url(node.index, evm, node.rpchost, node.ethwsport if evm else node.pubsubport)
        self.ws = None
        self.evm = evm

    async def subscribe(self, topic, *args):
        # connect if necessary
        if self.ws == None:
            self.ws = await websockets.connect(self.url)

        # subscribe
        method = "eth_subscribe" if self.evm else "cfx_subscribe"
        req = request_json(method, params=(topic, *args))
        await self.ws.send(req)
        resp = parse_json(await self.ws.recv())
        if isinstance(resp, Ok):
            id = resp.result
            self.buffer[id] = []
            return Subscription(self, id, self.evm)
        else:
            raise ReceivedErrorResponseError(resp)

class Subscription:
    def __init__(self, pubsub: PubSubClient, id: int, evm: bool):
        self.pubsub = pubsub
        self.id = id
        self.evm = evm

    async def unsubscribe(self):
        assert(self.pubsub.ws != None)

        # unsubscribe
        method = "eth_unsubscribe" if self.evm else "cfx_unsubscribe"
        req = request_json(method, params=(self.id,))
        await self.pubsub.ws.send(req)
        resp = parse_json(await self.pubsub.ws.recv())
        if isinstance(resp, Ok):
            assert(resp.result == True)
        else:
            raise ReceivedErrorResponseError(resp)

        # clear buffer
        del self.pubsub.buffer[self.id]

    async def next_wo_timeout(self):
        # return buffered if possible
        if len(self.pubsub.buffer[self.id]) > 0:
            return self.pubsub.buffer[self.id].pop()

        # receive new
        while True:
            resp = await self.pubsub.ws.recv()
            resp = json.loads(resp)

            recv_id = resp["params"]["subscription"]
            result = resp["params"]["result"]

            if recv_id == self.id:
                return result

            self.pubsub.buffer[recv_id].append(result)

    async def next(self, timeout=5.0):
        try:
            return await asyncio.wait_for(self.next_wo_timeout(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Received nothing on pub-sub {self.pubsub.url}/{self.id} (node: {self.pubsub.nid}) for {timeout} seconds.")

    async def iter(self, timeout=5):
        while True:
            try:
                yield await self.next(timeout=timeout)
            except TimeoutError:
                break
