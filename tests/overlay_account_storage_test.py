from cfx_utils import CFX
from conflux_web3.contract import ConfluxContract
from conflux_web3.contract.function import ConfluxContractFunction
from conflux.utils import *
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework

class OverlayAccountStorageTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
    
    def run_test(self):
        self.w3 = self.cw3
        self.genesis_key1 = self.core_accounts[0].key
        self.genesis_addr1 = self.core_accounts[0].address
        self.genesis_key2 = self.evm_accounts[0].key
        self.genesis_addr2 = self.cfx.account.from_key(self.evm_accounts[0].key).address

        accounts = self.initialize_accounts(2, value = 1000)

        self.genesis_key3 = accounts[0].key
        self.genesis_addr3 = self.cfx.address(accounts[0].address)
        self.genesis_key4 = accounts[1].key
        self.genesis_addr4 = self.cfx.address(accounts[1].address)
        
        self.w3.wallet.add_accounts([self.genesis_key2, self.genesis_key3, self.genesis_key4])

        
        def direct_call(call_fn, storage_contract, priv_key, before_value, after_value):
            return call_fn.transact({
                "from": self.cfx.account.from_key(priv_key).address,
            }).executed()
        
        self.run_task_group(direct_call)

        def read_then_call(call_fn: ConfluxContractFunction, storage_contract: ConfluxContract, priv_key, before_value, after_value):
            call_contract = self.cfx_contract("StorageExt")(call_fn.address)
            return call_contract.functions.multiCallExternal([
                storage_contract.functions.assertValue(0, before_value).encode_transaction_data(),
                call_fn.encode_transaction_data(),
            ], [
                storage_contract.address,
                call_fn.address,
            ]).transact({
                "from": self.cfx.account.from_key(priv_key).address,
            }).executed()
        
        
        self.run_task_group(read_then_call)

        def read_revert_then_call(call_fn: ConfluxContractFunction, storage_contract: ConfluxContract, priv_key, before_value, after_value):
            call_contract = self.cfx_contract("StorageExt")(call_fn.address)
            return call_contract.functions.multiCallExternalWithFlag([
                storage_contract.functions.assertValue(0, 999).encode_transaction_data(),
                call_fn.encode_transaction_data(),
            ], [
                storage_contract.address,
                call_fn.address,
            ], [2, 0]).transact({
                "from": self.cfx.account.from_key(priv_key).address,
            }).executed()
        
        self.run_task_group(read_revert_then_call)

        def revert_on_first_call(call_fn: ConfluxContractFunction, storage_contract: ConfluxContract, priv_key, before_value, after_value):
            call_contract = self.cfx_contract("StorageExt")(call_fn.address)
            call_data = call_fn.encode_transaction_data()
            reverted_call = call_contract.functions.callAnother(call_fn.address, call_data, 4).encode_transaction_data()
            return call_contract.functions.multiCallExternalWithFlag([
                storage_contract.functions.assertValue(0, before_value).encode_transaction_data(),
                reverted_call,
                storage_contract.functions.assertValue(0, before_value).encode_transaction_data(),
                call_data,
                storage_contract.functions.assertValue(0, after_value).encode_transaction_data(),
            ], [
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
            ], [0, 2, 0, 0, 0]).transact({
                "from": self.cfx.account.from_key(priv_key).address,
            }).executed()
        
        self.run_task_group(revert_on_first_call)

        def revert_on_second_call(call_fn: ConfluxContractFunction, storage_contract: ConfluxContract, priv_key, before_value, after_value):
            call_contract = self.cfx_contract("StorageExt")(call_fn.address)
            call_data = call_fn.encode_transaction_data()
            reverted_call = call_contract.functions.callAnother(call_fn.address, call_data, 4).encode_transaction_data()
            return call_contract.functions.multiCallExternalWithFlag([
                storage_contract.functions.assertValue(0, before_value).encode_transaction_data(),
                call_data,
                storage_contract.functions.assertValue(0, after_value).encode_transaction_data(),
                reverted_call,
                storage_contract.functions.assertValue(0, after_value).encode_transaction_data(),
            ], [
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
            ], [0, 0, 0, 2, 0]).transact({
                "from": self.cfx.account.from_key(priv_key).address,
            }).executed()
        
        self.run_task_group(revert_on_second_call)

        
    def run_task_group(self, customized_enactor):

        self.storage_contract = self.deploy_contract("StorageExt")
        self.another_contract = self.deploy_contract("StorageExt")

        storage_contract = self.storage_contract
        another_contract = self.another_contract
        
        self.customized_enactor = customized_enactor

        fn = storage_contract.functions.set(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key2, task_index = 0)
        assert_storage_occupied(receipt, self.genesis_addr2, 64)
        assert_equal(len(receipt["storageReleased"]), 0)

        fn = storage_contract.functions.change(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key2, task_index = 1)
        assert_storage_occupied(receipt, self.genesis_addr2, 0)
        assert_equal(len(receipt["storageReleased"]), 0)

        fn = storage_contract.functions.change(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key3, task_index = 2)
        assert_storage_occupied(receipt, self.genesis_addr3, 64)
        assert_storage_released(receipt, self.genesis_addr2, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

        self.internal_contract("SponsorWhitelistControl").functions.setSponsorForCollateral(storage_contract.address).transact({
            "value": CFX(1000)
        }).executed()
        storage_contract.functions.setSponsored(self.genesis_addr3).transact().executed()

        fn = storage_contract.functions.change(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key3, task_index = 3)
        assert_storage_occupied(receipt, storage_contract.address, 64)
        assert_storage_released(receipt, self.genesis_addr3, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

        fn = storage_contract.functions.change(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key4, task_index = 4)
        assert_storage_occupied(receipt, self.genesis_addr4, 64)
        assert_storage_released(receipt, storage_contract.address, 64)
        assert_equal(len(receipt["storageReleased"]), 1)


        fn = another_contract.functions.callAnother(storage_contract.address, storage_contract.functions.change(0).encode_transaction_data(), 0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key4, task_index = 5)
        assert_storage_occupied(receipt, self.genesis_addr4, 0)
        assert_equal(len(receipt["storageReleased"]), 0)

        self.internal_contract("SponsorWhitelistControl").functions.setSponsorForCollateral(another_contract.address).transact({
            "value": CFX(1000)
        }).executed()
        another_contract.functions.setSponsored(self.genesis_addr4).transact().executed()

        fn = another_contract.functions.callAnother(storage_contract.address, storage_contract.functions.change(0).encode_transaction_data(), 0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key4, task_index = 6)
        assert_storage_occupied(receipt, another_contract.address, 64)
        assert_storage_released(receipt, self.genesis_addr4, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

        fn = storage_contract.functions.change(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key3, task_index = 7)
        assert_storage_occupied(receipt, storage_contract.address, 64)
        assert_storage_released(receipt, another_contract.address, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

        fn = another_contract.functions.callAnother(storage_contract.address, storage_contract.functions.reset(0).encode_transaction_data(), 0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key2, task_index = 8)
        assert_storage_occupied(receipt, self.genesis_addr2, 0)
        assert_storage_released(receipt, storage_contract.address, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

    def customized_call(self, call_fn: ConfluxContractFunction, priv_key, task_index):
        before_value = task_index
        after_value = (task_index + 1) % 9
        assert_equal(self.storage_at(self.storage_contract.address, 0), before_value)
        receipt = self.customized_enactor(call_fn, self.storage_contract, priv_key, before_value, after_value)
        assert_equal(self.storage_at(self.storage_contract.address, 0), after_value)
        return receipt


    def storage_at(self, addr, key):
        result = self.cfx.get_storage_at(addr, key) 
        if result is None:
            return 0
        else:
            return int.from_bytes(result, "big")
        

        
if __name__ == "__main__":
    OverlayAccountStorageTest().main()