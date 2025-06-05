#!/usr/bin/env python3
import os

import json

from test_framework.mininode import *
from test_framework.util import *
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from conflux.config import default_config
from conflux.rpc import RpcClient
from test_framework.block_gen_thread import BlockGenThread

from web3 import Web3
from web3.middleware import SignAndSendRawMiddlewareBuilder
from web3.exceptions import ContractLogicError

CREATE_EMPTY_CONTRACT_DATA = "0x610000600081600b8239f3"
C2_TRANSITION_HEIGHT = 99

class Create2EvmTest(SmartContractBenchBase):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["c2_fix_transition_height"] = C2_TRANSITION_HEIGHT

    def setup_network(self):
        self.setup_nodes()

    def test_evm_create2(self, w3: Web3, redeploy_success: bool):
        create2contract = self.deploy_create2(w3)
        # call create2factory
        # deploy_data = "0x" + bytecode.strip()
        expected_addr = create2contract.functions.callCreate2(2, CREATE_EMPTY_CONTRACT_DATA).call()
        assert(len(expected_addr) == 42)
        assert w3.eth.get_code(expected_addr) == b''
        
        deploy_using_create2 = create2contract.functions.callCreate2(2, CREATE_EMPTY_CONTRACT_DATA).transact({
            "gasPrice": 10000,
        })
        assert(w3.eth.wait_for_transaction_receipt(deploy_using_create2)["status"] == 1)
        
        
        # call create2factory again, DIDN'T REVERT
        if redeploy_success:
        
            tx_hash = create2contract.functions.callCreate2(2, CREATE_EMPTY_CONTRACT_DATA).transact({
                "gasPrice": 10000,
            })
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
            assert receipt["status"] == 1
        else:
            try:
                deploy_using_create2 = create2contract.functions.callCreate2(2, CREATE_EMPTY_CONTRACT_DATA).transact({
                    "gasPrice": 10000,
                })
                assert False, "should revert"
            except ContractLogicError as e:
                assert e.message.startswith("execution reverted: revert: Failed to deploy contract using provided salt")
            except Exception as e:
                assert False, f"unexpected error: {e}"


    def deploy_create2(self, w3):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        metadata_file_path = os.path.join(file_dir, "test_contracts/artifacts/contracts/Create2Factory.sol/Create2Factory.json")
        with open(metadata_file_path, "r") as f:
            metadata = json.load(f)
        abi = metadata["abi"]
        bytecode = metadata["bytecode"]
        factory = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = factory.constructor().transact({
            "gasPrice": 10000,
        })
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        # factory deployed
        create2contract = factory(tx_receipt["contractAddress"])
        return create2contract

    def run_test(self):
        block_gen_thread = BlockGenThread(self.nodes, self.log)
        block_gen_thread.start()
        
        self.rpc = RpcClient(self.nodes[0])
        
        w3 = self.ew3
        assert w3.is_connected()
        self.priv_key = default_config["GENESIS_PRI_KEY"]
        account = w3.eth.account.from_key(self.priv_key)
        w3.eth.default_account = account.address
        w3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(account))

        self.test_evm_create2(w3, True)
        
        assert self.rpc.epoch_number() < self.conf_parameters["c2_fix_transition_height"]
        delta_blocks = self.conf_parameters["c2_fix_transition_height"] - self.rpc.epoch_number()
        self.log.info(f"generate {delta_blocks} blocks to transition height")
        self.rpc.generate_blocks(num_txs=1, num_blocks=delta_blocks)
        assert self.rpc.epoch_number() >= self.conf_parameters["c2_fix_transition_height"]
        self.test_evm_create2(w3, False)

        self.log.info("Pass")

if __name__ == "__main__":
    Create2EvmTest().main()
