from web3 import Web3
from web3.contract import Contract

import itertools
from conflux.utils import *
from test_framework.util import *
from test_framework.mininode import *
from test_framework.contracts import ConfluxTestFrameworkForContract, Account

SNAPSHOT_EPOCH = 60

def temp_address(number: int):
    return Web3.toChecksumAddress("{:#042x}".format(number + 100))


class ContractRemoveTest(ConfluxTestFrameworkForContract):
    def __init__(self):
        super().__init__()
        self.has_range_delete_bug = False
        self.has_collateral_bug = True

    @property
    def correct_wl_value(self):
        return not self.has_range_delete_bug
    
    @property
    def correct_wl_collateral(self):
        return not (self.has_collateral_bug or self.has_range_delete_bug)

    def set_test_params(self):
        super().set_test_params()
        
        self.conf_parameters["adaptive_weight_beta"] = "1"
        self.conf_parameters["timer_chain_block_difficulty_ratio"] = "3"
        self.conf_parameters["timer_chain_beta"] = "15"
        self.conf_parameters["dev_snapshot_epoch_count"] = str(SNAPSHOT_EPOCH)
        self.conf_parameters["anticone_penalty_ratio"] = "10"

        # Disable CIP-131 on test
        self.conf_parameters["next_hardfork_transition_number"] = 9999999

    def run_test(self):
        accounts: List[Account] = self.initialize_accounts(2, value = 1000)
        self.genesis_addr3 = accounts[0].address
        self.genesis_key3 = accounts[0].key
        self.genesis_addr4 = accounts[1].address
        self.genesis_key4 = accounts[1].key


        self.test_range_deletion_on_contract_remove(False)
        self.test_range_deletion_on_contract_remove(True)

        for (is_sponsored, has_range_delete_bug) in itertools.product([True, False], [True, False]):
            self.test_sponsor_whitelist_clear_on_contract_remove(is_sponsored, has_range_delete_bug)

        self.log.info("Done")

    def test_range_deletion_on_contract_remove(self, is_sponsored):
        self.log.info(f"Test storage clear, Sponsored {is_sponsored}")
        self.is_sponsored = is_sponsored
        self.storage_owner = self.genesis_addr

        self.test_change_storage_and_kill()
        self.test_reset_storage_and_kill()
        self.test_unchange_storage_and_kill()
        self.test_set_new_storage_and_kill()
        self.test_set_new_storage_and_later_kill()

    
    def test_sponsor_whitelist_clear_on_contract_remove(self, is_sponsored, has_range_delete_bug):
        self.log.info(f"Test whitelist clear, sponsored {is_sponsored}, has range deletion bug {has_range_delete_bug}")
        self.is_sponsored = is_sponsored
        self.has_range_delete_bug = has_range_delete_bug
        self.storage_owner = self.genesis_addr

        self.test_touch_whitelist_and_kill()
        self.test_set_again_whitelist_and_kill()
        self.test_reset_whitelist_and_kill()
        self.test_set_new_whitelist_and_kill()
        self.test_set_new_storage_and_later_kill()


    def test_change_storage_and_kill(self):
        storage_contract = self.deploy_contract_and_init(5)
        multi_calldata = [
            storage_contract.functions.change(3).data(),
            storage_contract.functions.change(4).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]

        if not self.is_sponsored:
            # The check of storage limit is earlier than kill contract. So even if the occupied entry is released in kill process, we still need enough storage_limit. 
            storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0, err_msg = "VmError(ExceedStorageLimit)")
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 64 * 2)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        assert_equal(self.exist_storage_at(2), False)
        assert_equal(self.exist_storage_at(4), False)


    def test_reset_storage_and_kill(self):
        storage_contract = self.deploy_contract_and_init(5)
        multi_calldata = [
            storage_contract.functions.reset(3).data(),
            storage_contract.functions.reset(4).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        assert_equal(self.exist_storage_at(2), False)
        assert_equal(self.exist_storage_at(4), False)


    def test_unchange_storage_and_kill(self):
        storage_contract = self.deploy_contract_and_init(5)
        multi_calldata = [
            storage_contract.functions.set(3).data(),
            storage_contract.functions.set(4).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        assert_equal(self.exist_storage_at(2), False)
        assert_equal(self.exist_storage_at(4), False)


    def test_set_new_storage_and_kill(self):
        storage_contract = self.deploy_contract_and_init(5)
        multi_calldata = [
            storage_contract.functions.set(5).data(),
            storage_contract.functions.set(6).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        if not self.is_sponsored:
            # The check of storage limit is earlier than kill contract. So even if the occupied entry is released in kill process, we still need enough storage_limit. 
            storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0, err_msg = "VmError(ExceedStorageLimit)")
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 64 * 2)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        assert_equal(self.exist_storage_at(2), False)
        assert_equal(self.exist_storage_at(6), False)


    def test_set_new_storage_and_later_kill(self):
        storage_contract = self.deploy_contract_and_init(5)
        multi_calldata = [
            storage_contract.functions.change(4).data(),
            storage_contract.functions.set(5).data(),
            storage_contract.functions.set(6).data(),
        ]
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 64 * 3)
        assert_storage_released(receipt, self.genesis_addr4, 64)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 3 * 64)
        assert_equal(self.exist_storage_at(2), True)
        assert_equal(self.exist_storage_at(4), True)
        assert_equal(self.exist_storage_at(6), True)

        receipt = storage_contract.functions.selfDestruct(self.genesis_addr3).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr4, 4 * 64)
        assert_storage_released(receipt, self.storage_owner, 3 * 64)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        assert_equal(self.exist_storage_at(2), False)
        assert_equal(self.exist_storage_at(4), False)
        assert_equal(self.exist_storage_at(6), False)


    def test_touch_whitelist_and_kill(self):
        storage_contract = self.deploy_contract_and_set_whitelist(5)
        multi_calldata = [
            storage_contract.functions.getSponsored(temp_address(3)).data(),
            storage_contract.functions.getSponsored(temp_address(4)).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0)
        # print(receipt)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5 if self.correct_wl_collateral else 64 * 2)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        self.assert_address_sponsored(storage_contract.address, 2, False if self.correct_wl_value else True)
        # Touch can also eliminate the influence from range deletion bug
        self.assert_address_sponsored(storage_contract.address, 4, False)


    def test_set_again_whitelist_and_kill(self):
        storage_contract = self.deploy_contract_and_set_whitelist(5)
        multi_calldata = [
            storage_contract.functions.setSponsored(temp_address(3)).data(),
            storage_contract.functions.setSponsored(temp_address(4)).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        if not self.is_sponsored:
            # The check of storage limit is earlier than kill contract. So even if the occupied entry is released in kill process, we still need enough storage_limit. 
            # For sponsor whitelist, the storage owner is changed even if the value does not change. This is a special case of storage owner behaviour
            storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0, err_msg = "VmError(ExceedStorageLimit)")
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 64 * 2)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5 if self.correct_wl_collateral else 64 * 2)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        self.assert_address_sponsored(storage_contract.address, 2, False if self.correct_wl_value else True)
        self.assert_address_sponsored(storage_contract.address, 4, False)


    def test_reset_whitelist_and_kill(self):
        storage_contract = self.deploy_contract_and_set_whitelist(5)
        multi_calldata = [
            storage_contract.functions.resetSponsored(temp_address(3)).data(),
            storage_contract.functions.resetSponsored(temp_address(4)).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5 if self.correct_wl_collateral else 64 * 2)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        self.assert_address_sponsored(storage_contract.address, 2, False if self.correct_wl_value else True)
        self.assert_address_sponsored(storage_contract.address, 4, False)


    def test_set_new_whitelist_and_kill(self):
        storage_contract = self.deploy_contract_and_set_whitelist(5)
        multi_calldata = [
            storage_contract.functions.setSponsored(temp_address(5)).data(),
            storage_contract.functions.setSponsored(temp_address(6)).data(),
            storage_contract.functions.selfDestruct(self.genesis_addr3).data()
        ]
        if not self.is_sponsored:
            # The check of storage limit is earlier than kill contract. So even if the occupied entry is released in kill process, we still need enough storage_limit. 
            storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 0, err_msg = "VmError(ExceedStorageLimit)")
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 64 * 2)
        assert_storage_released(receipt, self.genesis_addr4, 64 * 5 if self.correct_wl_collateral else 0)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        self.assert_address_sponsored(storage_contract.address, 2, False if self.correct_wl_value else True)
        self.assert_address_sponsored(storage_contract.address, 6, False)


    def test_set_new_whitelist_and_later_kill(self):
        start_epoch = self.client.epoch_number() // SNAPSHOT_EPOCH

        storage_contract = self.deploy_contract_and_set_whitelist(5)
        multi_calldata = [
            storage_contract.functions.setSponsored(temp_address(4)).data(),
            storage_contract.functions.setSponsored(temp_address(5)).data(),
            storage_contract.functions.setSponsored(temp_address(6)).data(),
        ]
        receipt = storage_contract.functions.multiCall(multi_calldata).cfx_transact(storage_limit = 64 * 3)
        assert_storage_released(receipt, self.genesis_addr4, 64)
        assert_storage_released(receipt, self.storage_owner, 0)
        assert_storage_occupied(receipt, self.storage_owner, 3 * 64)
        self.assert_address_sponsored(storage_contract.address, 2, True)
        self.assert_address_sponsored(storage_contract.address, 4, True)
        self.assert_address_sponsored(storage_contract.address, 6, True)

        if not self.has_range_delete_bug:
            self.client.generate_blocks(SNAPSHOT_EPOCH * 2 + 1)

        
        receipt = storage_contract.functions.selfDestruct(self.genesis_addr3).cfx_transact(storage_limit = 0)
        assert_storage_released(receipt, self.genesis_addr4, 4 * 64 if self.correct_wl_collateral else 0)
        assert_storage_released(receipt, self.storage_owner, 3 * 64 if self.correct_wl_collateral else 0)
        assert_storage_occupied(receipt, self.storage_owner, 0)
        if self.has_range_delete_bug:
            end_epoch = int(receipt["epochNumber"],0) // SNAPSHOT_EPOCH
            # If the test fails here, consider increase SNAPSHOT_EPOCH
            assert_greater_than(2, end_epoch - start_epoch)
        self.assert_address_sponsored(storage_contract.address, 2, False if self.correct_wl_value else True)
        self.assert_address_sponsored(storage_contract.address, 4, False if self.correct_wl_value else True)
        self.assert_address_sponsored(storage_contract.address, 6, False if self.correct_wl_value else True)
        

    def deploy_contract_and_init(self, num_entries):
        storage_contract: Contract = self.cfx_contract("StorageExt").deploy(transact_args=dict(priv_key = self.genesis_key3))

        multi_calldata = [storage_contract.functions.set(i).data() for i in range(num_entries)]
        storage_contract.functions.multiCall(multi_calldata).cfx_transact(priv_key = self.genesis_key4, storage_limit = 64 * num_entries)
        self.exist_storage_at = lambda x: self.client.get_storage_at(storage_contract.address.lower(), "{:#066x}".format(x)) is not None
        assert_equal(self.exist_storage_at(num_entries - 1), True)
        assert_equal(self.exist_storage_at(num_entries), False)
        
        if self.is_sponsored:
            storage_contract.functions.setSponsored(self.genesis_addr).cfx_transact(priv_key = self.genesis_key3, storage_limit = 64)
            self.internal_contract("SponsorWhitelistControl").functions.setSponsorForCollateral(storage_contract.address).cfx_transact(priv_key = self.genesis_key3, value = 100)
            self.storage_owner = storage_contract.address
        return storage_contract
    
    def deploy_contract_and_set_whitelist(self, num_entries):
        storage_contract: Contract = self.cfx_contract("StorageExt").deploy(transact_args=dict(priv_key = self.genesis_key3))

        multi_calldata = [storage_contract.functions.setSponsored(temp_address(i)).data() for i in range(num_entries)]
        storage_contract.functions.multiCall(multi_calldata).cfx_transact(priv_key = self.genesis_key4, storage_limit = 64 * num_entries)
        self.assert_address_sponsored(storage_contract.address, num_entries - 1, True)
        self.assert_address_sponsored(storage_contract.address, num_entries, False)

        if self.is_sponsored:
            storage_contract.functions.setSponsored(self.genesis_addr).cfx_transact(priv_key = self.genesis_key3, storage_limit = 64)
            self.internal_contract("SponsorWhitelistControl").functions.setSponsorForCollateral(storage_contract.address).cfx_transact(priv_key = self.genesis_key3, value = 100)
            self.storage_owner = storage_contract.address
        
        if not self.has_range_delete_bug:
            # We can not fix the range deletion bug now. We can only generate enough blocks to eliminate the influence of this bug.
            self.client.generate_blocks(SNAPSHOT_EPOCH * 2 + 1)
        return storage_contract
    
    def assert_address_sponsored(self, contract_address, sponsored_index: int, expected: bool):
        actual = self.internal_contract("SponsorWhitelistControl").functions.isWhitelisted(contract_address, temp_address(sponsored_index)).cfx_call()
        assert_equal(expected, actual)
        


if __name__ == "__main__":
    ContractRemoveTest().main()