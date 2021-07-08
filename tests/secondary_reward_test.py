#!/usr/bin/env python3
from conflux.rpc import RpcClient
from conflux.utils import priv_to_addr, parse_as_int
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_PATH = "contracts/simple_storage.dat"


class StorageMaintenanceTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.mining_author = "0x10000000000000000000000000000000000000aa"
        self.conf_parameters = {"mining_author": "\"10000000000000000000000000000000000000aa\"",
                                "mining_type": "'disable'"
                                }
        self.gasPrice = 1

    def setup_network(self):
        self.log.info("setup nodes ...")
        self.setup_nodes()

    def run_test(self):
        self.rpc = RpcClient(self.nodes[0])
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))
        block_reward = 7000000000000000000

        # deploy storage test contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert (os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        # 1. Produce an empty block
        self.rpc.generate_block()

        # 2. Deploy a contract: this will create 6 blocks and the first block contains 'create contract' transaction,
        # the other 5 blocks are empty.
        receipt, _ = self.deploy_contract(sender, priv_key, bytecode)

        # 3. Produce 10 empty blocks, and the miner's reward for the first block will be updated to world-state
        for _ in range(10): self.rpc.generate_block()
        balance = self.rpc.get_balance(self.mining_author)
        count = self.rpc.get_block_count()
        expected = block_reward
        self.log.info("block count: %d, balance: %d, expected: %d", count, balance, expected)
        assert_equal(balance, expected)

        # 4. Produce 1 empty block, and the miner will receive reward for the second block. This block reward should
        # contains transaction fee.
        self.rpc.generate_blocks(1)
        balance = self.rpc.get_balance(self.mining_author)
        count = self.nodes[0].getblockcount()
        transaction_fee = parse_as_int(receipt['gasFee'])
        expected += block_reward + transaction_fee
        self.log.info("block count: %d, balance: %d, expected: %d, transaction_fee: %d", count, balance, expected,
                transaction_fee)
        assert_equal(balance, expected)

        # 5. Produce 1 empty block, and the miner will receive reward for the third empty block. This block reward
        # should contains storage maintenance fee.
        self.rpc.generate_blocks(1)
        balance = self.rpc.get_balance(self.mining_author)
        count = self.nodes[0].getblockcount()
        collateral_for_storage = self.rpc.get_collateral_for_storage(sender)
        storage_fee = collateral_for_storage * 4 // 100 // 63072000
        expected += block_reward + storage_fee
        self.log.info("block count: %d, balance: %d, expected: %d, collateral_for_storage: %d, storage_fee: %d", count,
                balance, expected, collateral_for_storage, storage_fee)
        assert_equal(balance, expected)

        # 6. Produce 1 empty block, and the miner will receive reward for the forth empty block. This block reward
        # should contains storage maintenance fee.
        self.rpc.generate_blocks(1)
        balance = self.rpc.get_balance(self.mining_author)
        count = self.nodes[0].getblockcount()
        collateral_for_storage = self.rpc.get_collateral_for_storage(sender)
        storage_fee = collateral_for_storage * 4 // 100 // 63072000
        expected += storage_fee + block_reward
        self.log.info("block count: %d, balance: %d, expected: %d, collateral_for_storage: %d, storage_fee: %d", count,
                balance, expected, collateral_for_storage, storage_fee)

        assert_equal(balance, expected)

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc.new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, nonce=None,
                gas_price=self.gasPrice,
                storage_limit=20000)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address


if __name__ == "__main__":
    StorageMaintenanceTest().main()
