#!/usr/bin/env python3
from eth_utils import decode_hex

from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS, COLLATERAL_UNIT_IN_DRIP
from conflux.utils import encode_hex, priv_to_addr, parse_as_int
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3

class ClearAdminTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 8

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log)
        sync_blocks(self.nodes)
        self.rpc = RpcClient(self.nodes[0])

    def run_test(self):
        start_p2p_connection(self.nodes)
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()

        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS
        genesis_key = default_config["GENESIS_PRI_KEY"]
        genesis_addr = encode_hex_0x(priv_to_addr(genesis_key))
        nonce = 0
        test_account_key = default_config["GENESIS_PRI_KEY_2"]
        test_account_addr = encode_hex_0x(priv_to_addr(test_account_key))
        null_addr = "0x0000000000000000000000000000000000000000"

        file_dir = os.path.dirname(os.path.realpath(__file__))
        control_contract_file_path =os.path.join(file_dir, "..", "internal_contract", "metadata", "AdminControl.json")
        control_contract_dict = json.loads(open(control_contract_file_path, "r").read())
        admin_control_contract = get_contract_instance(contract_dict=control_contract_dict)
        admin_control_contract_addr = "0x0888000000000000000000000000000000000000"

        # Deploy a new instance of the create2factory other than the genesis block,
        # so that the admin is the genesis_addr, in order to test hijackAdmin function
        # in clear_admin_test_contract_addr.sol.
        self.tx_conf = {"from":Web3.toChecksumAddress(genesis_addr), "nonce":int_to_hex(nonce), "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        create2factory = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/create2factory_abi.json"),
            bytecode_file = os.path.join(file_dir, "contracts/create2factory_bytecode.dat"),
        )
        raw_create = create2factory.constructor().buildTransaction(self.tx_conf)
        tx_data = decode_hex(raw_create["data"])
        tx_create = create_transaction(pri_key=genesis_key, receiver=b'', nonce=nonce, gas_price=gas_price, data=tx_data, gas=gas, value=0, storage_limit=1920)
        nonce += 1
        self.rpc.send_tx(tx_create, True)
        receipt = self.rpc.get_transaction_receipt(tx_create.hash_hex())
        create2factory_addr = receipt['contractCreated']

        # Clear admin by non-admin (fail)
        self.log.info("Test unable to clear admin by non-admin.")
        set_admin = admin_control_contract.functions \
            .setAdmin(Web3.toChecksumAddress(create2factory_addr), null_addr) \
            .buildTransaction({"to":admin_control_contract_addr, **self.tx_conf})
        tx_data = set_admin["data"]
        self.call_contract(test_account_addr, test_account_key, admin_control_contract_addr, tx_data)
        assert_equal(self.rpc.get_admin(create2factory_addr), genesis_addr)

        clear_admin_test_contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/clear_admin_at_creation.json"),
            bytecode_file = os.path.join(file_dir, "contracts/clear_admin_at_creation.bytecode"),
        )

        self.log.info("Test contract creation by itself")
        raw_create = clear_admin_test_contract.constructor().buildTransaction(self.tx_conf)
        tx_data = decode_hex(raw_create["data"])
        tx_create = create_transaction(pri_key=genesis_key, receiver=b'', nonce=nonce, gas_price=gas_price, data=tx_data, gas=gas, value=0, storage_limit=1920)
        nonce += 1
        self.rpc.send_tx(tx_create, True)
        receipt = self.rpc.get_transaction_receipt(tx_create.hash_hex())
        address = receipt["contractCreated"]
        self.log.info("  contract created at %s" % address)
        assert(address is not None)

        self.log.info("Test clear admin at contract creation through create2factory")
        create_data = raw_create["data"]
        salt = 0
        data = create2factory.functions.deploy(create_data, salt).buildTransaction({"to":create2factory_addr, **self.tx_conf})["data"]
        # Compute the contract address.
        clear_admin_test_contract_addr = Web3.toChecksumAddress("0x" + self.rpc.call(create2factory_addr, data)[-40:])
        # Deploy the contract.
        self.call_contract(genesis_addr, genesis_key, create2factory_addr, data, value=0)
        assert_equal(self.rpc.get_admin(clear_admin_test_contract_addr), null_addr)
        # The owner of create2factory_addr isn't hijacked.
        self.log.info("Test unable to hijack set admin.")
        assert_equal(self.rpc.get_admin(create2factory_addr), genesis_addr)

        self.log.info("Test unable to hijack owner through deployAndHijackAdmin")
        # Create a new contract through deployAndHijackAdmin.
        new_contract_to_deploy = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/blackhole.json"),
            bytecode_file = os.path.join(file_dir, "contracts/blackhole.bytecode"),
        )
        self.tx_conf["nonce"] = 1
        self.tx_conf["from"] = Web3.toChecksumAddress(test_account_addr)
        new_raw_create = new_contract_to_deploy.constructor().buildTransaction(self.tx_conf)
        create_data = new_raw_create["data"]
        data = clear_admin_test_contract.functions.deployAndHijackAdmin(create_data).buildTransaction({"to":clear_admin_test_contract_addr, **self.tx_conf})["data"]
        new_contract_addr = "0x" + self.rpc.call(clear_admin_test_contract_addr, data)[-40:]
        self.call_contract(test_account_addr, test_account_key, clear_admin_test_contract_addr, data, value=123)
        # Check owner of the new contract isn't the "evil address" or null address.
        assert_equal(self.rpc.get_admin(new_contract_addr), test_account_addr)

        self.log.info("Pass")

    def call_contract(self, sender, priv_key, contract, data_hex, value=0, storage_limit=10000, gas=CONTRACT_DEFAULT_GAS):
        c0 = self.rpc.get_collateral_for_storage(sender)
        tx = self.rpc.new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, value=value, storage_limit=storage_limit, gas=gas)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        self.log.info("call_contract storage collateral change={}".format((self.rpc.get_collateral_for_storage(sender) - c0) // COLLATERAL_UNIT_IN_DRIP))
        return receipt

if __name__ == "__main__":
    ClearAdminTest().main()
