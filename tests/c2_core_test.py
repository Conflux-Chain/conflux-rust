#!/usr/bin/env python3
import os

from test_framework.mininode import *
from test_framework.blocktools import encode_hex_0x
from test_framework.util import *
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS, COLLATERAL_UNIT_IN_DRIP
from conflux.utils import priv_to_addr

from web3 import Web3

CREATE_EMPTY_CONTRACT_DATA = "0x610000600081600b8239f3"
C2_TRANSITION_HEIGHT = 99

class Create2CoreTest(SmartContractBenchBase):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["c2_fix_transition_height"] = C2_TRANSITION_HEIGHT

    def setup_network(self):
        self.setup_nodes()
        
    def test_core_create2(self, redeploy_outcome: str):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        metadata_file_path = os.path.join(file_dir, "test_contracts/artifacts/contracts/Create2Factory.sol/Create2Factory.json")
        with open(metadata_file_path, "r") as f:
            metadata = json.load(f)
        abi = metadata["abi"]
        bytecode = metadata["bytecode"]
        create2factory = Web3().eth.contract(abi=abi, bytecode=bytecode)
        constructor_data = create2factory.constructor().build_transaction(self.tx_conf)["data"]
        
        tx = self.rpc.new_tx(data=bytes.fromhex(constructor_data[2:]), receiver="", value=0, gas=200000, storage_limit=2048)
        tx_hash = self.rpc.send_tx(tx, True)
        receipt = self.rpc.get_transaction_receipt(tx_hash)
        # assert receipt["outcomeStatus"] == "0x0"
        assert receipt["contractCreated"] is not None
        create2factory_addr = receipt["contractCreated"]

        # deploy empty
        self.tx_conf["to"] = create2factory_addr
        data = create2factory.encode_abi("callCreate2", [2, CREATE_EMPTY_CONTRACT_DATA])
        result = self.rpc.call(create2factory_addr, data)
        assert(len(result) == 66)
        deployed_addr = "0x" + result[-40:]
        result = self.call_contract(self.sender, self.priv_key, create2factory_addr, data, 0, storage_limit=2048)
        assert(result["outcomeStatus"] == "0x0")

        # try deploy again
        code = self.rpc.get_code(deployed_addr).strip()
        assert(len(code) == 2)
        result = self.call_contract(self.sender, self.priv_key, create2factory_addr, data, 0, storage_limit=2048)
        assert result["outcomeStatus"] == redeploy_outcome

    def run_test(self):
        self.priv_key = default_config["GENESIS_PRI_KEY"]
        self.sender = encode_hex_0x(priv_to_addr(self.priv_key))
        self.sender_checksum = Web3.to_checksum_address(self.sender)
        self.rpc = RpcClient(self.nodes[0])
        gas = CONTRACT_DEFAULT_GAS
        gas_price = 10

        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.test_core_create2("0x0")

        # generate blocks to transition height
        delta_blocks = self.conf_parameters["c2_fix_transition_height"] - self.rpc.epoch_number()
        self.log.info(f"generate {delta_blocks} blocks to transition height")
        self.rpc.generate_blocks(num_txs=1, num_blocks=delta_blocks)
        assert self.rpc.epoch_number() >= self.conf_parameters["c2_fix_transition_height"]

        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.test_core_create2("0x1")
        self.log.info("Pass")

    def call_contract(self, sender, priv_key, contract, data_hex, value=0, storage_limit=0, gas=CONTRACT_DEFAULT_GAS):
        c0 = self.rpc.get_collateral_for_storage(sender)
        tx = self.rpc.new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, value=value, storage_limit=storage_limit, gas=gas)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        self.log.info("call_contract storage_limit={}".format((self.rpc.get_collateral_for_storage(sender) - c0) // COLLATERAL_UNIT_IN_DRIP))
        return receipt


if __name__ == "__main__":
    Create2CoreTest().main()
