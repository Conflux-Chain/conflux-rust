from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal, wait_until
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from conflux.config import default_config
from conflux.utils import priv_to_addr
from conflux.rpc import RpcClient
from test_framework.blocktools import encode_hex_0x


class TxPoolLargeNonceTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["tx_pool_nonce_bits"] = "128"

    def run_test(self):
        self.genesis_key = default_config["GENESIS_PRI_KEY"]
        self.genesis_addr = encode_hex_0x(priv_to_addr(self.genesis_key))
        self.client2 = RpcClient(self.nodes[1])

        tx = self.client.new_tx(receiver=self.genesis_addr, gas_price=1, nonce= 2 ** 129)

        self.test_rpc_send(tx)
        self.test_send_in_block(tx)

    def test_rpc_send(self, tx):
        try:
            self.client.send_tx(tx, False)
        except ReceivedErrorResponseError as e:
            error = e.response
            assert_equal(error.code, -32602)
            assert_equal(error.message, "Invalid parameters: tx \"TooLargeNonce\"")
            assert_equal(error.data, "\"TooLargeNonce\"")
        except Exception as e:
            raise AssertionError("Unexpected exception raised: " +
                                type(e).__name__)
        else:
            raise AssertionError("RPC should raise error")
    
    def test_send_in_block(self, tx):
        block_hash = self.client.generate_block_with_fake_txs([tx])
        wait_until(lambda: self.client.block_by_epoch("latest_mined")["hash"] == block_hash)
        wait_until(lambda: self.client2.block_by_epoch("latest_mined")["hash"] == block_hash)
        
        
if __name__ == "__main__":
    TxPoolLargeNonceTest().main()