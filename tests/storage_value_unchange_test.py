from conflux.utils import *
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework

class StorageValueUnchangeTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        
    def run_test(self):
        self.w3 = self.cw3
        self.genesis_addr = self.core_accounts[0].address
        self.genesis_addr2 = self.cfx.account.from_key(self.evm_secrets[0]).address
        self.w3.wallet.add_account(self.evm_secrets[0])
        
        storage_contract = self.deploy_contract("StorageExt")

        # If the storage value does not change, the storage owner remains unchanged
        receipt = storage_contract.functions.set(0).transact().executed()
        assert_storage_occupied(receipt, self.genesis_addr, 64)

        receipt = storage_contract.functions.set(0).transact({
            "from": self.genesis_addr2,
        }).executed()
        assert_equal(receipt["storageCollateralized"], 0)
        assert_equal(len(receipt["storageReleased"]), 0)

        receipt = storage_contract.functions.reset(0).transact({
            "from": self.genesis_addr2,
        }).executed()
        assert_storage_released(receipt, self.genesis_addr, 64)

        # However, the sponsor whitelist does not follow this rule
        receipt = storage_contract.functions.setSponsored(self.genesis_addr).transact().executed()
        assert_storage_occupied(receipt, self.genesis_addr, 64)

        receipt = storage_contract.functions.setSponsored(self.genesis_addr).transact({
            "from": self.genesis_addr2,
        }).executed()
        assert_storage_occupied(receipt, self.genesis_addr2, 64)
        assert_storage_released(receipt, self.genesis_addr, 64)

        receipt = storage_contract.functions.resetSponsored(self.genesis_addr).transact({
            "from": self.genesis_addr2,
        }).executed()
        assert_storage_released(receipt, self.genesis_addr2, 64)
        


if __name__ == "__main__":
    StorageValueUnchangeTest().main()