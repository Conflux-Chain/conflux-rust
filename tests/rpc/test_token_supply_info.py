import json
import os

import eth_utils
import sys

from eth_utils import decode_hex
from web3 import Web3

from conflux.config import default_config
from conflux.messages import Transactions
from test_framework.blocktools import create_transaction
from test_framework.util import assert_equal, get_contract_instance

sys.path.append("..")

from conflux.rpc import RpcClient


class TestTokenSupplyInfo(RpcClient):
    def test_token_supply_info(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))

        # Two test accounts and genesis accounts
        info = self.get_supply_info()
        assert_equal(int(info["totalIssued"], 16), 10000005000000000000000000000000000)
        assert_equal(int(info["totalStaking"], 16), 0)
        assert_equal(int(info["totalCollateral"], 16), 0)

        REQUEST_BASE = {
            'gas': 3_000_000,
            'gasPrice': 1,
            'chainId': 10,
            "value": 0,
        }
        tx_conf = REQUEST_BASE
        tx_conf["nonce"] = 0
        tx_conf["to"] = Web3.toChecksumAddress("0888000000000000000000000000000000000002")
        file_path = os.path.join(file_dir, "..", "..", "internal_contract", "metadata", "Staking.json")
        staking_contract_dict = json.loads(open(os.path.join(file_path), "r").read())
        staking_contract = get_contract_instance(contract_dict=staking_contract_dict)
        tx_data = decode_hex(staking_contract.functions.deposit(10 ** 18)
                             .buildTransaction(tx_conf)["data"])
        tx = self.new_tx(data=tx_data, gas=tx_conf["gas"], receiver=tx_conf["to"], value=0)
        self.send_tx(tx, True)
        # Stake 10**18 drip, and generating 5 blocks does not affect rewards
        info = self.get_supply_info()
        assert_equal(int(info["totalIssued"], 16), 10000005000000000000000000000000000)
        assert_equal(int(info["totalStaking"], 16), 10**18)
        assert_equal(int(info["totalCollateral"], 16), 0)

        file_dir = os.path.dirname(os.path.realpath(__file__))
        tx_conf["nonce"] = 1
        del tx_conf["to"]
        pay_contract = get_contract_instance(
            abi_file=os.path.join(file_dir, "../contracts/pay_abi.json"),
            bytecode_file=os.path.join(file_dir, "../contracts/pay_bytecode.dat"),
        )
        # deploy pay contract
        tx_data = decode_hex(pay_contract.constructor().buildTransaction(tx_conf)["data"])
        tx = self.new_tx(data=tx_data, gas=tx_conf["gas"], receiver='', storage_limit=512, value=0)
        self.send_tx(tx, True)
        # Collateral for pay_contract
        info = self.get_supply_info()
        assert_equal(int(info["totalIssued"], 16), 10000005000000000000000000000000000)
        assert_equal(int(info["totalStaking"], 16), 10**18)
        assert_equal(int(info["totalCollateral"], 16), 512 * 976562500000000)

        # 17 blocks [12 (REWARD_EPOCH_COUNT) + 5 (DEFERRED_STATE_COUNT)] will trigger the first reward computation.
        h = self.epoch_number()
        self.generate_blocks(17 - h)
        info = self.get_supply_info()
        assert_equal(int(info["totalIssued"], 16), 10000005000000007000000000000000000)
        assert_equal(int(info["totalStaking"], 16), 10**18)
        assert_equal(int(info["totalCollateral"], 16), 512 * 976562500000000)
