from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from conflux.utils import priv_to_addr
from test_framework.util import *
from test_framework.mininode import *


class NotEnoughGasPrice(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["tx_pool_min_native_tx_gas_price"] = 1_000_000_000

    def run_test(self):
        rpc = RpcClient(self.nodes[0])
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        tx = rpc.new_tx(receiver=sender, value=0, gas_price=1)

        try:
            rpc.send_tx(tx)
        except ReceivedErrorResponseError as e:
            r = e.response
            assert_equal(r.code, -32602)
            assert_equal(r.message, "Invalid parameters: tx \"transaction gas price 1 less than the minimum value 1000000000\"")
            assert_equal(r.data, "\"transaction gas price 1 less than the minimum value 1000000000\"")
        else:
            raise AssertionError("Send transaction should fail")


if __name__ == "__main__":
    NotEnoughGasPrice().main()
