#!/usr/bin/env python3
from http.client import CannotSendRequest
from eth_utils import decode_hex

from conflux.rpc import RpcClient
from conflux.utils import encode_hex, privtoaddr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3
from easysolc import Solc

class WithdrawDepositTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()
        sync_blocks(self.nodes)
    
    def get_block_number(self, client, tx_hash):
        receipt = client.get_transaction_receipt(tx_hash)
        epoch_number = receipt['epochNumber']
        assert epoch_number is not None
        block_hash = receipt['blockHash']
        blocks = []
        for epoch in range(epoch_number + 1):
            blocks.extend(client.block_hashes_by_epoch(client.EPOCH_NUM(epoch)))
        for (i, block) in enumerate(blocks):
            if block == block_hash:
                return i + 1
        return None


    def run_test(self):
        # Prevent easysolc from configuring the root logger to print to stderr
        self.log.propagate = False

        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        staking_contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/storage_interest_staking_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/storage_interest_staking_bytecode.dat"),
        )

        start_p2p_connection(self.nodes)

        self.log.info("Initializing contract")
        genesis_key = default_config["GENESIS_PRI_KEY"]
        genesis_addr = privtoaddr(genesis_key)
        nonce = 0
        gas_price = 1
        gas = 50000000
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        self.tx_conf = {"from":Web3.toChecksumAddress(encode_hex_0x(genesis_addr)), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}

        # Setup balance for node 0
        node = self.nodes[0]
        client = RpcClient(node)
        (addr, priv_key) = client.rand_account()
        self.log.info("addr=%s priv_key=%s", addr, priv_key)
        tx = client.new_tx(value=5 * 10 ** 18, receiver=addr)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        assert_equal(node.cfx_getBalance(addr), hex(5000000000000000000))
        assert_equal(node.cfx_getStakingBalance(addr), hex(0))

        self.tx_conf["to"] = Web3.toChecksumAddress("843c409373ffd5c0bec1dddb7bec830856757b65")
        # deposit 10**18
        tx_data = decode_hex(staking_contract.functions.deposit(10 ** 18).buildTransaction(self.tx_conf)["data"])
        tx = client.new_tx(value=0, sender=addr, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        deposit_time = self.get_block_number(client, tx.hash_hex())
        assert_equal(node.cfx_getStakingBalance(addr), hex(10 ** 18))
        assert_equal(node.cfx_getBalance(addr), hex(4 * 10 ** 18 - gas))

        # withdraw 5 * 10**17
        balance = int(node.cfx_getBalance(addr), 16)
        tx_data = decode_hex(staking_contract.functions.withdraw(5 * 10 ** 17).buildTransaction(self.tx_conf)["data"])
        tx = client.new_tx(value=0, sender=addr, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        withdraw_time = self.get_block_number(client, tx.hash_hex())
        duration = withdraw_time - deposit_time
        total_num_blocks = 2 * 60 * 60 * 24 * 365
        interest = 5 * 10 ** 17 * duration * 252288000 // (total_num_blocks * 100) // total_num_blocks
        service_charge = 5 * 10 ** 17 * (total_num_blocks - duration) * 5 // 10000 // total_num_blocks
        assert_equal(node.cfx_getStakingBalance(addr), hex(5 * 10 ** 17))
        assert_equal(node.cfx_getBalance(addr), hex(balance + 5 * 10 ** 17 + interest - service_charge - gas))

        # lock 4 * 10 ** 17 for 1 day
        balance = int(node.cfx_getBalance(addr), 16)
        tx_data = decode_hex(staking_contract.functions.lock(4 * 10 ** 17, 1).buildTransaction(self.tx_conf)["data"])
        tx = client.new_tx(value=0, sender=addr, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        assert_equal(node.cfx_getBalance(addr), hex(balance - gas))
        assert_equal(node.cfx_getStakingBalance(addr), hex(5 * 10 ** 17))

        # withdraw 5 * 10**17 and it should fail
        balance = int(node.cfx_getBalance(addr), 16)
        tx_data = decode_hex(staking_contract.functions.withdraw(5 * 10 ** 17).buildTransaction(self.tx_conf)["data"])
        tx = client.new_tx(value=0, sender=addr, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        assert_equal(node.cfx_getBalance(addr), hex(balance - gas))
        assert_equal(node.cfx_getStakingBalance(addr), hex(5 * 10 ** 17))

        # withdraw 10**17 + 1 and it should fail
        balance = int(node.cfx_getBalance(addr), 16)
        tx_data = decode_hex(staking_contract.functions.withdraw(10 ** 17 + 1).buildTransaction(self.tx_conf)["data"])
        tx = client.new_tx(value=0, sender=addr, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        assert_equal(node.cfx_getBalance(addr), hex(balance - gas))
        assert_equal(node.cfx_getStakingBalance(addr), hex(5 * 10 ** 17))

        # withdraw 10**17 and it should succeed
        balance = int(node.cfx_getBalance(addr), 16)
        tx_data = decode_hex(staking_contract.functions.withdraw(10 ** 17).buildTransaction(self.tx_conf)["data"])
        tx = client.new_tx(value=0, sender=addr, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
        client.send_tx(tx)
        self.wait_for_tx([tx])
        withdraw_time = self.get_block_number(client, tx.hash_hex())
        duration = withdraw_time - deposit_time
        interest = 10 ** 17 * duration * 252288000 // (total_num_blocks * 100) // total_num_blocks
        service_charge = 10 ** 17 * (total_num_blocks - duration) * 5 // 10000 // total_num_blocks
        assert_equal(node.cfx_getBalance(addr), hex(balance + 10 ** 17 + interest - service_charge - gas))
        assert_equal(node.cfx_getStakingBalance(addr), hex(4 * 10 ** 17))

        block_gen_thread.stop()
        block_gen_thread.join()
        sync_blocks(self.nodes)
        self.log.info("Pass")

    def wait_for_tx(self, all_txs):
        for tx in all_txs:
            self.log.debug("Wait for tx to confirm %s", tx.hash_hex())
            for i in range(3):
                try:
                    retry = True
                    while retry:
                        try:
                            wait_until(lambda: checktx(self.nodes[0], tx.hash_hex()), timeout=20)
                            retry = False
                        except CannotSendRequest:
                            time.sleep(0.01)
                    break
                except AssertionError as _:
                    self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx]))
                if i == 2:
                        raise AssertionError("Tx {} not confirmed after 30 seconds".format(tx.hash_hex()))
        # After having optimistic execution, get_receipts may get receipts with not deferred block, these extra blocks
        # ensure that later get_balance can get correct executed balance for all transactions
        client = RpcClient(self.nodes[0])
        for _ in range(5):
            client.generate_block()

if __name__ == "__main__":
    WithdrawDepositTest().main()
