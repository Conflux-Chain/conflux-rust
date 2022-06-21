import sys
sys.path.append("..")

from conflux.address import hex_to_b32_address
from conflux.rpc import RpcClient
from test_framework.util import *

class TestEstimateAndCall(RpcClient):

    def test_estimate(self):
        to = self.rand_addr()
        call_request = {
            "to": hex_to_b32_address(to),
            "value": hex(100),
            "gasPrice": hex(100),
        }
        estimate_res = self.node.cfx_estimateGasAndCollateral(call_request)
        assert_equal(estimate_res["gasUsed"], "0x5208")

        call_request["from"] = hex_to_b32_address(self.rand_addr())

        assert_raises_rpc_error(-32015, "Can not estimate: transaction can not be executed", self.node.cfx_estimateGasAndCollateral, call_request)

    def test_call(self):
        to = self.rand_addr()
        call_request = {
            "to": hex_to_b32_address(to),
            "value": hex(100),
            "gasPrice": hex(100),
        }
        call_res = self.node.cfx_call(call_request)
        assert_equal(call_res, "0x")

        call_request["from"] = hex_to_b32_address(self.rand_addr())
        assert_raises_rpc_error(-32015, None, self.node.cfx_call, call_request)

    def test_call_with_large_price(self):
        to = self.rand_addr()
        call_request = {
            "from": hex_to_b32_address(to),
            "to": hex_to_b32_address(to),
            "value": hex(100),
            "gasPrice": hex(2**255),
            "storageLimit": hex(2**64-1)
        }
        assert_raises_rpc_error(-32015, None, self.node.cfx_call, call_request)

    def test_estimate_with_large_price(self):
        to = self.rand_addr()
        call_request = {
            "from": hex_to_b32_address(to),
            "to": hex_to_b32_address(to),
            "value": hex(100),
            "gasPrice": hex(2**255),
            "storageLimit": hex(2**64-1)
        }
        assert_raises_rpc_error(-32015, None, self.node.cfx_estimateGasAndCollateral, call_request)
