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

    def before_test(self):
        self.rpc = self.nodes[0].rpc
        self.enable_max_priority_fee_per_gas()
        self.setup_w3()
        self.w3 = self.cw3
