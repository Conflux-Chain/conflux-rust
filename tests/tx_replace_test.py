from test_framework.test_framework import ConfluxTestFramework
from conflux.config import default_config
from conflux.utils import priv_to_addr
from test_framework.blocktools import encode_hex_0x


class TxReplaceTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.genesis_key = default_config["GENESIS_PRI_KEY"]
        self.genesis_addr = encode_hex_0x(priv_to_addr(self.genesis_key))

        tx = self.client.new_tx(receiver=self.genesis_addr, gas_price=20, nonce=0)
        self.client.send_tx(tx, False)

        tx2 = self.client.new_tx(receiver=self.genesis_addr, gas_price=21, nonce=0)
        self.client.send_tx(tx2, False)
        
if __name__ == "__main__":
    TxReplaceTest().main()