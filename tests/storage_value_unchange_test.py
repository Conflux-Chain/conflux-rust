from web3 import Web3
from web3.contract import ContractFunction, Contract

from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.util import *
from test_framework.mininode import *
from test_framework.contracts import ConfluxTestFrameworkForContract

class StorageValueUnchangeTest(ConfluxTestFrameworkForContract):
    def run_test(self):
        storage_contract: Contract = self.cfx_contract("StorageExt").deploy()

        # If the storage value does not change, the storage owner remains unchanged
        receipt = storage_contract.functions.set(0).cfx_transact(storage_limit = 64)
        assert_storage_occupied(receipt, self.genesis_addr, 64)

        receipt = storage_contract.functions.set(0).cfx_transact(priv_key = self.genesis_key2, storage_limit = 0)
        assert_equal(receipt["storageCollateralized"], 0)
        assert_equal(len(receipt["storageReleased"]), 0)

        receipt = storage_contract.functions.reset(0).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr, 64)

        # However, the sponsor whitelist does not follow this rule
        receipt = storage_contract.functions.setSponsored(self.genesis_addr).cfx_transact(storage_limit = 64)
        assert_storage_occupied(receipt, self.genesis_addr, 64)

        receipt = storage_contract.functions.setSponsored(self.genesis_addr).cfx_transact(priv_key = self.genesis_key2, storage_limit = 64)
        assert_storage_occupied(receipt, self.genesis_addr2, 64)
        assert_storage_released(receipt, self.genesis_addr, 64)

        receipt = storage_contract.functions.resetSponsored(self.genesis_addr).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr2, 64)
        


if __name__ == "__main__":
    StorageValueUnchangeTest().main()