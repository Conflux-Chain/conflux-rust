from web3 import Web3
from web3.contract import ContractFunction, Contract

from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.util import *
from test_framework.mininode import *
from test_framework.contracts import ConfluxTestFrameworkForContract, Account

class OverlayAccountStorageTest(ConfluxTestFrameworkForContract):
    def run_test(self):
        accounts: List[Account] = self.initialize_accounts(2, value = 1000)
        self.genesis_key3 = accounts[0].key
        self.genesis_addr3 = accounts[0].address
        self.genesis_key4 = accounts[1].key
        self.genesis_addr4 = accounts[1].address

        
        def direct_call(call_fn, storage_contract, priv_key, before_value, after_value):
            return call_fn.cfx_transact(priv_key=priv_key)
        
        self.run_task_group(direct_call)

        def read_then_call(call_fn: ContractFunction, storage_contract: Contract, priv_key, before_value, after_value):
            call_contract: Contract = self.cfx_contract("StorageExt").at(call_fn.address)
            return call_contract.functions.multiCallExternal([
                storage_contract.functions.assertValue(0, before_value).data(),
                call_fn.data(),
            ], [
                storage_contract.address,
                call_fn.address,
            ]).cfx_transact(priv_key=priv_key)
        
        
        self.run_task_group(read_then_call)

        def read_revert_then_call(call_fn: ContractFunction, storage_contract: Contract, priv_key, before_value, after_value):
            call_contract: Contract = self.cfx_contract("StorageExt").at(call_fn.address)
            return call_contract.functions.multiCallExternalWithFlag([
                storage_contract.functions.assertValue(0, 999).data(),
                call_fn.data(),
            ], [
                storage_contract.address,
                call_fn.address,
            ], [2, 0]).cfx_transact(priv_key=priv_key)
        
        self.run_task_group(read_revert_then_call)

        def revert_on_first_call(call_fn: ContractFunction, storage_contract: Contract, priv_key, before_value, after_value):
            call_contract: Contract = self.cfx_contract("StorageExt").at(call_fn.address)
            call_data = call_fn.data()
            reverted_call = call_contract.functions.callAnother(call_fn.address, call_data, 4).data()
            return call_contract.functions.multiCallExternalWithFlag([
                storage_contract.functions.assertValue(0, before_value).data(),
                reverted_call,
                storage_contract.functions.assertValue(0, before_value).data(),
                call_data,
                storage_contract.functions.assertValue(0, after_value).data(),
            ], [
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
            ], [0, 2, 0, 0, 0]).cfx_transact(priv_key=priv_key)
        
        self.run_task_group(revert_on_first_call)

        def revert_on_second_call(call_fn: ContractFunction, storage_contract: Contract, priv_key, before_value, after_value):
            call_contract: Contract = self.cfx_contract("StorageExt").at(call_fn.address)
            call_data = call_fn.data()
            reverted_call = call_contract.functions.callAnother(call_fn.address, call_data, 4).data()
            return call_contract.functions.multiCallExternalWithFlag([
                storage_contract.functions.assertValue(0, before_value).data(),
                call_data,
                storage_contract.functions.assertValue(0, after_value).data(),
                reverted_call,
                storage_contract.functions.assertValue(0, after_value).data(),
            ], [
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
                call_fn.address,
                storage_contract.address,
            ], [0, 0, 0, 2, 0]).cfx_transact(priv_key=priv_key)
        
        self.run_task_group(revert_on_second_call)

        
    def run_task_group(self, customized_enactor):

        self.storage_contract: Contract = self.cfx_contract("StorageExt").deploy()
        self.another_contract: Contract = self.cfx_contract("StorageExt").deploy()

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

        self.internal_contract("SponsorWhitelistControl").functions.setSponsorForCollateral(storage_contract.address).cfx_transact(value = 1000)
        storage_contract.functions.setSponsored(self.genesis_addr3).cfx_transact()

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


        fn = another_contract.functions.callAnother(storage_contract.address, storage_contract.functions.change(0).data(), 0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key4, task_index = 5)
        assert_storage_occupied(receipt, self.genesis_addr4, 0)
        assert_equal(len(receipt["storageReleased"]), 0)

        self.internal_contract("SponsorWhitelistControl").functions.setSponsorForCollateral(another_contract.address).cfx_transact(value = 1000)
        another_contract.functions.setSponsored(self.genesis_addr4).cfx_transact()

        fn = another_contract.functions.callAnother(storage_contract.address, storage_contract.functions.change(0).data(), 0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key4, task_index = 6)
        assert_storage_occupied(receipt, another_contract.address, 64)
        assert_storage_released(receipt, self.genesis_addr4, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

        fn = storage_contract.functions.change(0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key3, task_index = 7)
        assert_storage_occupied(receipt, storage_contract.address, 64)
        assert_storage_released(receipt, another_contract.address, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

        fn = another_contract.functions.callAnother(storage_contract.address, storage_contract.functions.reset(0).data(), 0)
        receipt = self.customized_call(fn, priv_key = self.genesis_key2, task_index = 8)
        assert_storage_occupied(receipt, self.genesis_addr2, 0)
        assert_storage_released(receipt, storage_contract.address, 64)
        assert_equal(len(receipt["storageReleased"]), 1)

    def customized_call(self, call_fn: ContractFunction, priv_key, task_index):
        before_value = task_index
        after_value = (task_index + 1) % 9
        assert_equal(self.storage_at(self.storage_contract.address, 0), before_value)
        receipt = self.customized_enactor(call_fn, self.storage_contract, priv_key, before_value, after_value)
        assert_equal(self.storage_at(self.storage_contract.address, 0), after_value)
        return receipt


    def storage_at(self, addr, key):
        result = self.client.get_storage_at(addr.lower(), "{:#066x}".format(key)) 
        if result is None:
            return 0
        else:
            return int(result, 0)
        

        
if __name__ == "__main__":
    OverlayAccountStorageTest().main()