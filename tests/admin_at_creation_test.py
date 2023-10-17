#!/usr/bin/env python3
from test_framework.block_gen_thread import BlockGenThread
from test_framework.contracts import ConfluxTestFrameworkForContract, ZERO_ADDRESS, Contract
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

class ClearAdminTest(ConfluxTestFrameworkForContract):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 8

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        genesis_addr = self.genesis_addr
        test_account_key = self.genesis_key2
        test_account_addr = self.genesis_addr2
        create2factory_addr = self.create2factory.address

        # Clear admin by non-admin (fail)
        self.log.info("Test unable to clear admin by non-admin.")
        self.adminControl.functions.setAdmin(create2factory_addr, ZERO_ADDRESS).cfx_transact(priv_key=test_account_key)
        assert_equal(self.client.get_admin(create2factory_addr), genesis_addr.lower())


        self.log.info("Test contract creation by itself")
        clear_admin_test_contract: Contract = self.cfx_contract("AdminTestContract").deploy()
        self.log.info("  contract created at %s" % clear_admin_test_contract.address)

        self.log.info("Test clear admin at contract creation through create2factory")
        # Deploy the contract.
        clear_admin_test_contract2: Contract = self.cfx_contract("AdminTestContract").deploy2(seed = 0)
        assert_equal(self.client.get_admin(clear_admin_test_contract2.address), ZERO_ADDRESS)
        # The owner of create2factory_addr isn't hijacked.
        self.log.info("Test unable to hijack set admin.")
        assert_equal(self.client.get_admin(create2factory_addr), genesis_addr.lower())

        self.log.info("Test unable to hijack owner through deployAndHijackAdmin")
        # Create a new contract through deployAndHijackAdmin.
        create_data = self.cfx_contract("BlackHole").constructor().data()

        fn_call = clear_admin_test_contract.functions.deployAndHijackAdmin(create_data)
        created_address = fn_call.cfx_call(sender = test_account_addr)
        fn_call.cfx_transact(priv_key = test_account_key, value = 123, decimals = 1)
        assert_equal(self.client.get_admin(created_address), test_account_addr.lower())

        self.log.info("Pass")

if __name__ == "__main__":
    ClearAdminTest().main()
