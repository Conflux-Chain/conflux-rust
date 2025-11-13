#!/usr/bin/env python3
"""
Test for issue #3340: eth_estimateGas should return 
"insufficient funds for transfer" instead of "SenderDoesNotExist"
when the account has no prior transactions and zero balance.
"""
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from test_framework.util import *
from conflux.config import default_config
from base import Web3Base
from conflux.rpc import RpcClient
from web3 import Web3

class Issue3340Test(Web3Base):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["evm_chain_id"] = str(10)
        self.conf_parameters["evm_transaction_block_ratio"] = str(1)

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(0, ["--archive"])
        self.rpc = RpcClient(self.nodes[0])
        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/', request_kwargs={
            "proxies": {
                "http": "",
                "https": "",
            }
        }))
        assert_equal(self.w3.is_connected(), True)

    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        self.log.info(f'Using Conflux account {self.cfxAccount}')

        # Initialize an EVM account with a key that has never been used
        new_account_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        new_account = self.w3.eth.account.from_key(new_account_key)
        self.log.info(f'New EVM account (no balance, no transactions): {new_account.address}')

        # Verify the account has zero balance
        balance = self.w3.eth.get_balance(new_account.address)
        assert_equal(balance, 0, "Account should have zero balance")
        self.log.info(f'Account balance: {balance}')

        # Initialize another account as the recipient
        recipient_key = "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        recipient_account = self.w3.eth.account.from_key(recipient_key)
        self.log.info(f'Recipient account: {recipient_account.address}')

        # Try to estimate gas for a transaction from an account with no balance
        # This should return "insufficient funds" error, not "SenderDoesNotExist"
        try:
            estimate = self.w3.eth.estimate_gas({
                "from": new_account.address,
                "to": recipient_account.address,
                "value": 10000000000000000,  # 0.01 ETH
                "maxFeePerGas": 50000000000,
                "maxPriorityFeePerGas": 10000000000,
            })
            raise AssertionError("Expected eth_estimateGas to fail with insufficient funds error")
        except Exception as e:
            error_message = str(e)
            self.log.info(f'Error message: {error_message}')
            
            # The error should mention insufficient funds, not SenderDoesNotExist
            assert "SenderDoesNotExist" not in error_message, \
                f"Error should not contain 'SenderDoesNotExist', got: {error_message}"
            
            # Should contain "insufficient funds" similar to Ethereum
            assert "insufficient funds" in error_message.lower(), \
                f"Error should contain 'insufficient funds', got: {error_message}"
            
            self.log.info("✓ Test passed: eth_estimateGas returns 'insufficient funds' error")

if __name__ == "__main__":
    Issue3340Test().main()
