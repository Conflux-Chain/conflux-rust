from dataclasses import dataclass
from typing import List

from conflux_web3 import Web3 as CWeb3

from test_framework.test_framework import ConfluxTestFramework, RpcClient
from test_framework.util import *

BASE = int(1e18)
ZERO_ADDRESS = f"0x{'0'*40}"

@dataclass
class Account:
    address: str
    key: str

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

    def initialize_accounts(self, number = 10, value = 100) -> List[Account]:
        def initialize_new_account() -> Account:
            (address, priv) = self.client.rand_account()
            if value > 0:
                self.cfx_transfer(address, value = value)
            return Account(address, priv)
        
        return [initialize_new_account() for _ in range(number)]
