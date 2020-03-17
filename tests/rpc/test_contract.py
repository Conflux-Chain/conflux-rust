import eth_utils
import sys
import os
sys.path.append("..")

import eth_utils
from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import privtoaddr, int_to_hex
from test_framework.util import assert_equal, assert_is_hash_string
from web3 import Web3
from easysolc import Solc

class TestContract(RpcClient):

    def test_contract_deploy(self) -> str:
        # test simple storage contract with default value (5)
        tx = self.new_contract_tx("", "0x608060405234801561001057600080fd5b50600560008190555060e6806100276000396000f3fe6080604052600436106043576000357c01000000000000000000000000000000000000000000000000000000009004806360fe47b11460485780636d4ce63c14607f575b600080fd5b348015605357600080fd5b50607d60048036036020811015606857600080fd5b810190808035906020019092919050505060a7565b005b348015608a57600080fd5b50609160b1565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea165627a7a72305820b5180d95fdc3813028ed47f62c7cdf708b76c0db094043f533b42a430d313e150029")
        assert_equal(self.send_tx(tx, True), tx.hash_hex())

        contract_addr = self.get_tx(tx.hash_hex())["contractCreated"]
        assert_equal(len(contract_addr), 42)

        return contract_addr

    def test_estimate_gas(self):
        contract_addr = self.test_contract_deploy()
        gas = self.estimate_gas(contract_addr, "0x6d4ce63c") # get storage
        assert gas > self.DEFAULT_TX_GAS

    def test_call_result(self):
        contract_addr = self.test_contract_deploy()
        
        # get storage, default is 5
        result = self.call(contract_addr, "0x6d4ce63c")
        assert_equal(int(result, 0), 5)

        # set storage to 6
        result = self.call(contract_addr, "0x60fe47b10000000000000000000000000000000000000000000000000000000000000006")
        assert_equal(result, "0x")

    def test_contract_call(self):
        contract_addr = self.test_contract_deploy()
        assert_equal(int(self.call(contract_addr, "0x6d4ce63c"), 0), 5)

        # send tx to set the storage from 5 to 6
        tx = self.new_contract_tx(contract_addr, "0x60fe47b10000000000000000000000000000000000000000000000000000000000000006")
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        assert_equal(int(self.call(contract_addr, "0x6d4ce63c"), 0), 6)

        # send tx to set the storage from 6 to 7
        old_epoch = self.epoch_number()
        old_nonce = self.get_nonce(self.GENESIS_ADDR)
        tx2 = self.new_contract_tx(contract_addr, "0x60fe47b10000000000000000000000000000000000000000000000000000000000000007")
        assert_equal(self.send_tx(tx2, True), tx2.hash_hex())
        assert_equal(int(self.call(contract_addr, "0x6d4ce63c"), 0), 7)

        # verify the history storage value with specified nonce and epoch
        assert_equal(int(self.call(contract_addr, "0x6d4ce63c", nonce=old_nonce, epoch=self.EPOCH_NUM(old_epoch)), 0), 6)
