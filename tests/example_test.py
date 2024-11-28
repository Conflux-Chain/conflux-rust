#!/usr/bin/env python3
"""An example functional test
"""
from cfx_account import Account as CfxAccount
from eth_account import Account as EthAccount

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self._add_genesis_secrets(1, "core")
        self._add_genesis_secrets(1, "evm")

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        genesis = self.nodes[0].best_block_hash()
        self.log.info(genesis)
        
        core_accounts = [CfxAccount.from_key(secret, 10) for secret in self.core_secrets]
        assert len(core_accounts) == 2
        evm_accounts = [EthAccount.from_key(secret) for secret in self.evm_secrets]
        assert len(evm_accounts) == 2

        for acct in core_accounts:
            assert_equal(int(self.nodes[0].cfx_getBalance(acct.address), 16), 10000000000000000000000)
        for acct in evm_accounts:
            assert_equal(int(self.nodes[0].eth_getBalance(acct.address), 16), 10000000000000000000000)

        self.nodes[0].test_generateEmptyBlocks(1)
        assert (self.nodes[0].test_getBlockCount() == 2)
        besthash = self.nodes[0].best_block_hash()

        self.nodes[1].test_generateEmptyBlocks(2)
        assert (self.nodes[1].test_getBlockCount() == 3)

        connect_nodes(self.nodes, 0, 1)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].test_getBlockCount() == 4)

        self.nodes[0].test_generateEmptyBlocks(1)
        self.nodes[1].test_generateEmptyBlocks(1)
        sync_blocks(self.nodes[0:2])
        assert (self.nodes[0].test_getBlockCount() == 6)
        assert (self.nodes[1].test_getBlockCount() == 6)


if __name__ == '__main__':
    ExampleTest().main()
