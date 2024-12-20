from conflux_web3 import Web3 as CWeb3

from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *

BASE = int(1e18)
ZERO_ADDRESS = f"0x{'0'*40}"

class ConfluxTestFrameworkForContract(ConfluxTestFramework):
    
    w3: CWeb3
    
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["executive_trace"] = "true"

    def assert_tx_exec_error(self, tx_hash, err_msg):
        self.client.wait_for_receipt(tx_hash)
        receipt = self.client.get_transaction_receipt(tx_hash)
        assert_equal(
            receipt["txExecErrorMsg"],
            err_msg
        )

    def before_test(self):
        super().before_test()
        self.rpc = self.nodes[0].rpc
        self.enable_max_priority_fee_per_gas()
        self.setup_w3()
        self.w3 = self.cw3

    def initialize_accounts(self, number = 10, value = 100):
        """
        Not recommended now. It is now recommended to use `self._add_genesis_account` 
        during param setting phase to add genesis accounts.
        
        The generated accounts can be used from self.core_accounts or self.evm_accounts.
        """
        def initialize_new_account():
            acct = self.cfx.account.create()
            if value > 0:
                self.cfx_transfer(acct.hex_address, value = value)
            return acct
        
        return [initialize_new_account() for _ in range(number)]
