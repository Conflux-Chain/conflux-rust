#!/usr/bin/env python3
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class ClearAdminTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 8
        self._add_genesis_secrets(1, "core")

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)

    def run_test(self):
        self.start_block_gen()
        self.deploy_create2()

        genesis_addr = self.core_accounts[0].address
        test_account = self.core_accounts[1]
        test_account_addr = self.core_accounts[1].address
        create2factory_addr = self.create2factory.address

        # Clear admin by non-admin (fail)
        self.log.info("Test unable to clear admin by non-admin.")
        self.internal_contract("AdminControl").functions.setAdmin(create2factory_addr, ZERO_ADDRESS).transact({
            "from": test_account.address
        })
        assert_equal(self.cfx.get_admin(create2factory_addr), genesis_addr)


        self.log.info("Test contract creation by itself")
        clear_admin_test_contract = self.deploy_contract("AdminTestContract")
        self.log.info("  contract created at %s" % clear_admin_test_contract.address)

        self.log.info("Test clear admin at contract creation through create2factory")
        # Deploy the contract.
        clear_admin_test_contract2 = self.deploy_contract_2("AdminTestContract", 0)
        assert_equal(self.cfx.get_admin(clear_admin_test_contract2.address).hex_address, ZERO_ADDRESS)  # type: ignore
        # The owner of create2factory_addr isn't hijacked.
        self.log.info("Test unable to hijack set admin.")
        assert_equal(self.cfx.get_admin(create2factory_addr), genesis_addr)

        self.log.info("Test unable to hijack owner through deployAndHijackAdmin")
        # Create a new contract through deployAndHijackAdmin.
        create_data = self.cfx_contract("BlackHole").constructor()._encode_data_in_transaction()

        fn_call = clear_admin_test_contract.functions.deployAndHijackAdmin(create_data)
        created_address = fn_call.call({"from": test_account_addr})
        fn_call.transact({"from": test_account.address, "value": 123}).executed()
        assert_equal(self.cfx.get_admin(created_address), test_account_addr)

        self.log.info("Pass")

if __name__ == "__main__":
    ClearAdminTest().main()
