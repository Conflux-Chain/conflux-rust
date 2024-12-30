from decimal import Decimal
from cfx_utils import CFX
from conflux.utils import *
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework

BASE = int(1e18)
CIP107_NUMBER = 100
CIP104_PERIOD = 100
ZERO_ADDRESS = f"0x{'0'*40}"


class CheckCollateral:
    def __init__(self, framework: "CIP107Test", account):
        self.framework = framework
        self.account = account

        self.total_collateral = None
        self.total_storage_point = None
        self.used_storage_point = None

        self.account_unused_collateral = None
        self.account_used_collateral = None
        self.account_unused_storage_point = None
        self.account_used_storage_point = None

        self.total_issued = None

        self.tick()

    def tick(self):
        client = self.framework.client
        cfx = self.framework.cfx
        collateralInfo = cfx.get_collateral_info()
        self.total_storage_point = collateralInfo["convertedStoragePoints"]
        self.total_collateral = collateralInfo["totalStorageTokens"]
        self.total_used_storage_point = collateralInfo["usedStoragePoints"]

        self.account_used_storage_point = cfx.get_sponsor_info(
            self.account)["usedStoragePoints"]
        self.account_unused_storage_point = cfx.get_sponsor_info(
            self.account)["availableStoragePoints"]
        self.account_used_collateral = int(cfx.get_collateral_for_storage(
            self.account))
        self.account_unused_collateral = cfx.get_sponsor_info(
            self.account)["sponsorBalanceForCollateral"].value

        # Compute adjusted total_issued, elimating influence from block reward and storage interest
        supplyInfo = cfx.get_supply_info()

        x = supplyInfo["totalIssued"].value // (BASE//160) * (BASE//160)
        x -= client.epoch_number() * 2 * BASE
        self.total_issued = x

    def checked_tick(self, **kwargs):
        storage_point_attrs = ["total_storage_point", "total_used_storage_point",
                               "account_used_storage_point", "account_unused_storage_point"]
        collateral_attrs = ["total_collateral", "total_issued",
                            "account_used_collateral", "account_unused_collateral"]
        attrs = storage_point_attrs + collateral_attrs
        old = dict()
        for attr in attrs:
            old[attr] = getattr(self, attr)

        self.tick()

        for attr in attrs:
            if attr in kwargs and kwargs[attr] is None:
                continue

            actual_diff = getattr(self, attr) - old[attr]
            if attr in storage_point_attrs:
                expect_diff = kwargs.get(attr, 0) * 64
            else:
                expect_diff = kwargs.get(attr, 0) * BASE / 16

            if int(actual_diff) != int(expect_diff):
                raise AssertionError(
                    f"Assert attribute {attr} failed: expected {int(expect_diff)}, actual {int(actual_diff)}: {old[attr]} --> {getattr(self, attr)}")

        actual_value = self.framework.sponsorControl.functions.getAvailableStoragePoints(
            self.account).call()
        assert_equal(self.account_unused_storage_point, actual_value)

    def __str__(self):
        return f'''
total_collateral\t{self.total_collateral / BASE}
total_storage_point\t{self.total_storage_point}
total_used_storage_point\t{self.total_used_storage_point}
account_used_storage_point\t{self.account_used_storage_point / 64}
account_unused_storage_point\t{self.account_unused_storage_point / 64}
account_used_collateral\t{self.account_used_collateral / BASE * 16}
account_unused_collateral\t{self.account_unused_collateral / BASE * 16}'''


class StorageContract:
    def __init__(self, framework: "CIP107Test", seed=0):
        self.framework = framework
        self.storage = framework.deploy_contract_2("Storage", seed).functions

    def set_sponsor(self, value):
        sponsorContract = self.framework.sponsorControl.functions
        sponsorContract.addPrivilegeByAdmin(
            self.storage.address, [ZERO_ADDRESS]).transact().executed()
        sponsorContract.setSponsorForCollateral(
            self.storage.address).transact({
                "value": CFX(Decimal(value))
            }).executed()

    def set_entry(self, index):
        if isinstance(index, list):
            for i in index:
                self.storage.change(i).transact({
                    "storageLimit": 64
                }).executed()
        else:
            self.storage.change(index).transact({
                "storageLimit": 64
            }).executed()

    def reset_entry(self, index):
        if isinstance(index, list):
            for i in index:
                self.storage.reset(i).transact({
                    "storageLimit": 64
                }).executed()
        else:
            self.storage.reset(index).transact({
                "storageLimit": 64
            }).executed()

    def suicide(self):
        adminControl = self.framework.internal_contract("AdminControl").functions
        adminControl.destroy(self.storage.address).transact().executed()

    def address(self):
        return self.storage.address


class CIP107Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["executive_trace"] = "true"
        self.conf_parameters["cip107_transition_number"] = CIP107_NUMBER
        self.conf_parameters["cip118_transition_number"] = 1
        self.conf_parameters["params_dao_vote_period"] = CIP104_PERIOD
        self.conf_parameters["dao_vote_transition_number"] = 1
        self.conf_parameters["dao_vote_transition_height"] = 1

    def run_test(self):
        self.w3 = self.cw3
        self.sponsorControl = self.internal_contract(name="SponsorWhitelistControl")
        self.deploy_create2()
        # Task 1: test if the collateral can be maintained correctly
        self.test_collateral_maintain()

        # Task 2: test change sponsor
        self.test_change_sponsor()

        # Task 3: test the parameter update
        self.test_params_update()

    def test_change_sponsor(self):
        storage = StorageContract(self, seed=1)
        check = CheckCollateral(self, storage.address())

        storage.set_sponsor(0.25)
        check.checked_tick(
            total_storage_point=2, total_collateral=None, total_issued=-2, account_unused_collateral=2, account_unused_storage_point=2)
        
        acct = self.cfx.account.from_key(self.evm_accounts[0].key)
        self.w3.wallet.add_account(acct)

        self.sponsorControl.functions.setSponsorForCollateral(storage.address()).transact({
            "value": CFX(Decimal(0.5)),
            "from": acct.address
        }).executed()
        check.checked_tick(
            total_storage_point=3, total_collateral=None, total_issued=-3, account_unused_collateral=3, account_unused_storage_point=3)

    def test_params_update(self):
        # Deploy new contract
        storage = StorageContract(self, seed=2)
        check = CheckCollateral(self, storage.address())

        stakingControl = self.internal_contract("Staking").functions
        paramsControl = self.internal_contract("ParamsControl").functions

        # Obtain DAO Votes
        stakingControl.deposit(1_000_000 * BASE).transact().executed()
        current_block_number = int(self.client.get_status()["blockNumber"], 0)
        locked_time = 5 * 15_768_000  # MINED_BLOCK_COUNT_PER_QUARTER
        stakingControl.voteLock(
            1_000_000 * BASE, current_block_number + locked_time).transact().executed()

        # Set block number to the middle of a voting period
        vote_tick = int((self.client.epoch_number() + CIP104_PERIOD / 2) //
                        CIP104_PERIOD * CIP104_PERIOD + CIP104_PERIOD / 2)
        self.wait_for_block(vote_tick)

        # Vote
        current_round = paramsControl.currentRound().call()
        paramsControl.castVote(current_round, [{"topic_index": 2, "votes": [
                               0, 1_000_000 * BASE, 0]}]).transact().executed()

        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=30, total_issued=-30, total_collateral=None, account_unused_collateral=30, account_unused_storage_point=30)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 1, have_not_reach=True)
        paramsControl.castVote(
            current_round + 1, [{"topic_index": 2, "votes": [0, 1_000_000 * BASE, 0]}]).transact().executed()
        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=30, total_issued=-30, total_collateral=None, account_unused_collateral=30, account_unused_storage_point=30)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 2, have_not_reach=True)
        paramsControl.castVote(
            current_round + 2, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]).transact().executed()
        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=40, total_issued=-40, total_collateral=None, account_unused_collateral=20, account_unused_storage_point=40)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 3, have_not_reach=True)
        paramsControl.castVote(
            current_round + 3, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]).transact().executed()
        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=48, total_issued=-48, total_collateral=None, account_unused_collateral=12, account_unused_storage_point=48)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 4, have_not_reach=True)
        paramsControl.castVote(
            current_round + 4, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]).transact().executed()
        self.wait_for_block(vote_tick + CIP104_PERIOD * 5, have_not_reach=True)
        paramsControl.castVote(
            current_round + 5, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]).transact().executed()
        self.wait_for_block(vote_tick + CIP104_PERIOD * 7, have_not_reach=True)

        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=12, total_issued=-12, total_collateral=None, account_unused_collateral=48, account_unused_storage_point=12)

    def test_collateral_maintain(self):
        storage = StorageContract(self)
        check = CheckCollateral(self, storage.address())

        self.log.info("User set 1")
        storage.set_entry(1)
        check.checked_tick(total_collateral=1)

        self.log.info("Set Sponsor")
        storage.set_sponsor(0.25)
        check.checked_tick(total_collateral=None,
                           account_unused_collateral=4)  # TODO: check None

        self.log.info("Set 1,2")
        storage.set_entry([1, 2])
        check.checked_tick(
            total_collateral=1, account_unused_collateral=-2, account_used_collateral=2)

        self.log.info("Reset 1")
        storage.reset_entry(1)
        check.checked_tick(
            total_collateral=-1, account_unused_collateral=1, account_used_collateral=-1)

        self.wait_for_block(CIP107_NUMBER, have_not_reach=True)

        self.log.info("Set 1")
        storage.set_entry(1)
        check.checked_tick(total_collateral=1, total_issued=-2, total_storage_point=2, account_unused_collateral=-
                           3, account_used_collateral=1, account_unused_storage_point=2)

        self.log.info("Reset 1,2")
        storage.reset_entry([1, 2])
        check.checked_tick(
            total_collateral=-2, account_unused_collateral=2, account_used_collateral=-2)

        self.log.info("Set 1,2,3")
        storage.set_entry([1, 2, 3])
        check.checked_tick(total_collateral=2, total_used_storage_point=1, account_unused_collateral=-2,
                           account_used_collateral=2, account_unused_storage_point=-1, account_used_storage_point=1)

        self.log.info("Set Sponsor")
        storage.set_sponsor(0.25)
        check.checked_tick(
            total_storage_point=2, total_issued=-2, account_unused_collateral=2, account_unused_storage_point=2)

        self.log.info("Set 4,5,6")
        storage.set_entry([4, 5, 6])
        check.checked_tick(total_collateral=2, total_used_storage_point=1, account_unused_collateral=-2,
                           account_used_collateral=2, account_unused_storage_point=-1, account_used_storage_point=1)

        self.log.info("Reset 1,2,3")
        storage.reset_entry([1, 2, 3])
        check.checked_tick(total_collateral=-1, total_used_storage_point=-2, account_unused_collateral=1,
                           account_used_collateral=-1, account_unused_storage_point=2, account_used_storage_point=-2)

        self.log.info("Set 7,8")
        storage.set_entry([7, 8])
        check.checked_tick(total_collateral=1, total_used_storage_point=1, account_unused_collateral=-1,
                           account_used_collateral=1, account_unused_storage_point=-1, account_used_storage_point=1)

        storage.suicide()
        storage = StorageContract(self)
        check.checked_tick(total_collateral=-4, total_issued=-1, total_used_storage_point=-1, account_unused_collateral=None,
                           account_used_collateral=-4, account_unused_storage_point=None, account_used_storage_point=-1)

    def wait_for_block(self, block_number, have_not_reach=False):
        if have_not_reach:
            assert_greater_than_or_equal(
                block_number,  self.client.epoch_number())
        while self.client.epoch_number() < block_number:
            self.client.generate_blocks(
                block_number - self.client.epoch_number())
            time.sleep(0.1)
            self.log.info(f"block_number: {self.client.epoch_number()}")

    def wait_for_cip107_activation(self):
        self.wait_for_block(CIP107_NUMBER, have_not_reach=True)


if __name__ == "__main__":
    CIP107Test().main()
