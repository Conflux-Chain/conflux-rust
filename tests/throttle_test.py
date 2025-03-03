#!/usr/bin/env python3

import os
import time
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError

from test_framework.test_framework import ConfluxTestFramework
from conflux.rpc import RpcClient

class ThrottleRpcTests(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters = {
            "throttling_conf": "\"../throttling.toml\""
        }

    def setup_chain(self):
        # prepare throttling configuratoin file
        throttle_conf = os.path.join(self.options.tmpdir, "throttling.toml")
        # Note: Should not use cfx_getBestBlockHash for this test, because it has been called to start a node.
        with open(throttle_conf, "w") as fp:
            fp.write("[rpc_local]\n")
            fp.write("cfx_epochNumber=\"300,200,1,100,1\"\n")
            fp.write("cfx_gasPrice=\"5,5,2,1,0\"\n")
            # In python tests, we will only call the local RPC interface,
            # just add the public rpc section as a placeholder.
            fp.write("[rpc]")

        self.conf_parameters["throttling_conf"] = "'{}'".format(throttle_conf)

        ConfluxTestFramework.setup_chain(self)

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        client = RpcClient(self.nodes[0])
        self.test_throttled(client)
        self.test_recharged(client)

    def test_throttled(self, client):
        # allow 2 times
        assert client.epoch_number() == 0
        assert client.epoch_number() == 0

        # throttled
        try:
            client.epoch_number()
            assert "should be throttled"
        except ReceivedErrorResponseError as e:
            assert e.response.code == -32072
            assert e.response.data.startswith("throttled in ")

    # allow to tolerate 1 time even throttled
        try:
            client.epoch_number()
            assert "should be throttled"
        except ReceivedErrorResponseError as e:
            assert e.response.code == -32072
            assert e.response.data.startswith("throttled in ")

        # already throttled
        try:
            client.epoch_number()
            assert "should be throttled"
        except ReceivedErrorResponseError as e:
            assert e.response.code == -32072
            assert e.response.data == "already throttled, please try again later"

    def test_recharged(self, client):
        # allow 5 times
        for _ in range(5):
            assert client.gas_price() is not None

        # throttled
        try:
            client.gas_price()
            assert "should be throttled"
        except ReceivedErrorResponseError as e:
            assert e.response.code == -32072
            assert e.response.data.startswith("throttled in ")

        # do not tolerate once throttled
        try:
            client.gas_price()
            assert "should be throttled"
        except ReceivedErrorResponseError as e:
            assert e.response.code == -32072
            assert e.response.data == "already throttled, please try again later"

        # sleep 1 second to recharge tokens
        time.sleep(1)

        # 2 tokens recharged
        assert client.gas_price() is not None
        assert client.gas_price() is not None

        # throttled again
        try:
            client.gas_price()
            assert "should be throttled"
        except ReceivedErrorResponseError as e:
            assert e.response.code == -32072
            assert e.response.data.startswith("throttled in ")

if __name__ == "__main__":
    ThrottleRpcTests().main()