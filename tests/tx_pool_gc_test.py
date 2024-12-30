from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal



class TxPoolGarbageCollectTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["tx_pool_size"] = "5"

    def run_test(self):
        accounts = self.initialize_accounts(number = 11)
        addr = accounts[0].hex_address
        for i in range(1, 11):
            self.cfx_transfer(addr, 1, (i+10)  * (10**9), priv_key=accounts[i].key, execute=False)

        assert_equal(self.client.txpool_status(), (5, 5))

        for i in range(0, 5):
            self.cfx_transfer(addr, 1, 21 * (10**9), priv_key=accounts[0].key, nonce = i, execute=False)
        
        assert_equal(self.client.txpool_status(), (5, 1))
        for i in range(1, 11):
            self.cfx_transfer(addr, 1, (i+30)  * (10**9), priv_key=accounts[i].key, execute=False)

        assert_equal(self.client.txpool_status(), (5, 5))

if __name__ == "__main__":
    TxPoolGarbageCollectTest().main()