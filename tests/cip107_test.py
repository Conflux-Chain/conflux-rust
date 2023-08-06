from web3 import Web3
from web3.contract import ContractFunction, Contract

from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *
from conflux.address import hex_to_b32_address, b32_address_to_hex


from os.path import dirname, realpath, join

BASE = int(1e18)
CIP107_NUMBER = 100
CIP104_PERIOD = 100
ZERO_ADDRESS = f"0x{'0'*40}"


def add_contract_address(contract, address):
    w3 = Web3()
    return w3.eth.contract(abi=contract.abi, bytecode=contract.bytecode, address=Web3.toChecksumAddress(address))


def get_admin_contract():
    file_path = os.path.join(os.path.dirname(
        __file__), "..", "internal_contract", "metadata", "AdminControl.json")
    contract_dict = json.loads(open(file_path, "r").read())
    return get_contract_instance(contract_dict=contract_dict, address="0x0888000000000000000000000000000000000000")


def get_sponsor_contract():
    file_path = os.path.join(os.path.dirname(
        __file__), "..", "internal_contract", "metadata", "SponsorWhitelistControl.json")
    contract_dict = json.loads(open(file_path, "r").read())
    return get_contract_instance(contract_dict=contract_dict, address="0x0888000000000000000000000000000000000001")


def get_staking_contract():
    file_path = os.path.join(os.path.dirname(
        __file__), "..", "internal_contract", "metadata", "Staking.json")
    contract_dict = json.loads(open(file_path, "r").read())
    return get_contract_instance(contract_dict=contract_dict, address="0x0888000000000000000000000000000000000002")


def get_dao_contract():
    file_path = os.path.join(os.path.dirname(
        __file__), "..", "internal_contract", "metadata", "ParamsControl.json")
    contract_dict = json.loads(open(file_path, "r").read())
    return get_contract_instance(contract_dict=contract_dict, address="0x0888000000000000000000000000000000000007")


def get_create2factory_contract():
    abi_file = os.path.join(os.path.dirname(__file__),
                            "contracts", "simple_create2_factory.abi")
    bytecode_file = os.path.join(os.path.dirname(
        __file__), "contracts", "simple_create2_factory.bytecode")
    return get_contract_instance(abi_file=abi_file, bytecode_file=bytecode_file)


def get_storage_contract():
    abi_file = os.path.join(os.path.dirname(__file__),
                            "contracts", "storage_test_for_cip107.json")
    bytecode_file = os.path.join(os.path.dirname(
        __file__), "contracts", "storage_test_for_cip107.bytecode")
    return get_contract_instance(abi_file=abi_file, bytecode_file=bytecode_file)


class CheckCollateral:
    def __init__(self, framework, account):
        self.rpc = framework.rpc
        self.client = framework.client
        self.read_contract = framework.read_contract
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
        collateralInfo = self.client.get_collateral_info()
        self.total_storage_point = int(
            collateralInfo["convertedStoragePoints"], 0)
        self.total_collateral = int(collateralInfo["totalStorageTokens"], 0)
        self.total_used_storage_point = int(
            collateralInfo["usedStoragePoints"], 0)

        self.account_used_storage_point = self.client.get_used_storage_points(
            self.account)
        self.account_unused_storage_point = self.client.get_unused_storage_points(
            self.account)
        self.account_used_collateral = self.client.get_collateral_for_storage(
            self.account)
        self.account_unused_collateral = self.client.get_sponsor_balance_for_collateral(
            self.account)

        # Compute adjusted total_issued, elimating influence from block reward and storage interest
        supplyInfo = self.client.get_supply_info()

        x = int(supplyInfo["totalIssued"], 0) // (BASE//160) * (BASE//160)
        x -= self.client.epoch_number() * 2 * BASE
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

            if actual_diff != expect_diff:
                raise AssertionError(
                    f"Assert attribute {attr} failed: expected {expect_diff}, actual {actual_diff}: {old[attr]} --> {getattr(self, attr)}")
        
        assert_equal(self.account_unused_storage_point, int(self.read_contract(get_sponsor_contract().functions.getAvailableStoragePoints(self.account)),0))

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
    def __init__(self, framework, seed=0):
        self.framework = framework
        storage = get_storage_contract()
        receipt = framework.call_contract(
            framework.create2factory.functions.callCreate2(seed, storage.bytecode))
        created_address = b32_address_to_hex([t for t in framework.rpc.trace_transaction(
            receipt["transactionHash"]) if t["type"] == "create_result"][0]["action"]["addr"])
        storage = add_contract_address(storage, created_address)
        self.storage = storage

    def set_sponsor(self, value):
        self.framework.call_contract(get_sponsor_contract().functions.addPrivilegeByAdmin(self.storage.address, [ZERO_ADDRESS]))
        self.framework.call_contract(get_sponsor_contract().functions.setSponsorForCollateral(self.storage.address), value=value)

    def set_entry(self, index):
        if isinstance(index, list):
            for i in index:
                self.framework.call_contract(
                    self.storage.functions.change(i), storage_limit=64)
        else:
            self.framework.call_contract(
                self.storage.functions.change(index), storage_limit=64)

    def reset_entry(self, index):
        if isinstance(index, list):
            for i in index:
                self.framework.call_contract(
                    self.storage.functions.reset(i), storage_limit=64)
        else:
            self.framework.call_contract(
                self.storage.functions.reset(index), storage_limit=64)

    def suicide(self):
        self.framework.call_contract(
            get_admin_contract().functions.destroy(self.storage.address))

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
        start_p2p_connection(self.nodes)
        self.rpc = self.nodes[0].rpc
        self.client = RpcClient(self.nodes[0])

        create2factory = get_create2factory_contract()
        receipt = self.call_contract(create2factory.constructor())
        self.create2factory = add_contract_address(
            create2factory, receipt["contractCreated"])

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

        self.call_contract(get_sponsor_contract().functions.setSponsorForCollateral(
            storage.address()), value=0.5, priv_key=-1)
        check.checked_tick(
            total_storage_point=3, total_collateral=None, total_issued=-3, account_unused_collateral=3, account_unused_storage_point=3)

    def test_params_update(self):
        # Deploy new contract
        storage = StorageContract(self, seed=2)
        check = CheckCollateral(self, storage.address())

        # Obtain DAO Votes
        self.call_contract(get_staking_contract().functions.deposit(1_000_000 * BASE))
        current_block_number = int(self.client.get_status()["blockNumber"], 0)
        locked_time = 5 * 15_768_000  # MINED_BLOCK_COUNT_PER_QUARTER
        self.call_contract(get_staking_contract().functions.voteLock(
            1_000_000 * BASE, current_block_number + locked_time))

        # Set block number to the middle of a voting period
        vote_tick = int((self.client.epoch_number() + CIP104_PERIOD / 2) //
                        CIP104_PERIOD * CIP104_PERIOD + CIP104_PERIOD / 2)
        self.wait_for_block(vote_tick)

        # Vote
        current_round = int(self.read_contract(
            get_dao_contract().functions.currentRound()), 0)
        self.call_contract(get_dao_contract().functions.castVote(
            current_round, [{"topic_index": 2, "votes": [0, 1_000_000 * BASE, 0]}]))

        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=30, total_issued=-30, total_collateral=None, account_unused_collateral=30, account_unused_storage_point=30)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 1, have_not_reach=True)
        self.call_contract(get_dao_contract().functions.castVote(
            current_round + 1, [{"topic_index": 2, "votes": [0, 1_000_000 * BASE, 0]}]))
        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=30, total_issued=-30, total_collateral=None, account_unused_collateral=30, account_unused_storage_point=30)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 2, have_not_reach=True)
        self.call_contract(get_dao_contract().functions.castVote(
            current_round + 2, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]))
        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=40, total_issued=-40, total_collateral=None, account_unused_collateral=20, account_unused_storage_point=40)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 3, have_not_reach=True)
        self.call_contract(get_dao_contract().functions.castVote(
            current_round + 3, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]))
        storage.set_sponsor(3.75)
        check.checked_tick(
            total_storage_point=48, total_issued=-48, total_collateral=None, account_unused_collateral=12, account_unused_storage_point=48)

        self.wait_for_block(vote_tick + CIP104_PERIOD * 4, have_not_reach=True)
        self.call_contract(get_dao_contract().functions.castVote(
            current_round + 4, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]))
        self.wait_for_block(vote_tick + CIP104_PERIOD * 5, have_not_reach=True)
        self.call_contract(get_dao_contract().functions.castVote(
            current_round + 5, [{"topic_index": 2, "votes": [0, 0, 1_000_000 * BASE]}]))
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

    def read_contract(self, contract_function: ContractFunction):
        tx = contract_function.build_transaction(
            {"gas": 3000000, "gasPrice": 1, "chainId": 1})
        return self.client.call(tx["to"], tx["data"])

    def call_contract(self, contract_function: ContractFunction, value=None, decimals: int = 18, gas=None, storage_limit=None, priv_key=None):
        tx = contract_function.build_transaction(
            {"gas": 3000000, "gasPrice": 1, "chainId": 1})
        data = bytes.fromhex(tx["data"][2:])

        if value is not None:
            value = int(value * (10**decimals))
        else:
            value = 0

        if storage_limit is None:
            if len(tx["to"]) == 0:
                storage_limit = 30000
            else:
                storage_limit = 1024

        if gas is None:
            if len(tx["to"]) == 0:
                gas = 10_000_000
            else:
                gas = 3_000_000

        if len(tx["to"]) == 0:
            receiver = None
        else:
            receiver = tx["to"]

        if gas is None:
            if len(data) > 0:
                gas = 3000000
            else:
                gas = 21000

        tx = self.client.new_contract_tx(
            receiver=receiver, value=value, data_hex=tx["data"], priv_key=priv_key, gas=gas, storage_limit=storage_limit)
        self.client.send_tx(tx, True)
        self.wait_for_tx([tx], True)
        receipt = self.client.get_transaction_receipt(tx.hash_hex())
        # self.log.info(receipt)
        return receipt


if __name__ == "__main__":
    CIP107Test().main()
