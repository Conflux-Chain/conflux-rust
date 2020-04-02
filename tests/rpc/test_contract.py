import eth_utils
import sys
import os
sys.path.append("..")

from conflux.config import default_config
from conflux.rpc import RpcClient
from conflux.utils import priv_to_addr, int_to_hex, encode_hex
from test_framework.util import assert_equal, assert_is_hash_string
from web3 import Web3

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
    
    def test_estimate_collateral(self):
        contract_addr = self.test_contract_deploy()
        (addr, priv_key) = self.rand_account()

        collateral = self.estimate_collateral(
            contract_addr="0x",
            data_hex="0x60806040526000805534801561001457600080fd5b506040516101b73803806101b78339818101604052602081101561003757600080fd5b810190808051906020019092919050505080600081905550506101588061005f6000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80636d4ce63c146100465780637b0cb83914610064578063812600df1461006e575b600080fd5b61004e6100b0565b6040518082815260200191505060405180910390f35b61006c6100b9565b005b61009a6004803603602081101561008457600080fd5b810190808035906020019092919050505061010b565b6040518082815260200191505060405180910390f35b60008054905090565b3373ffffffffffffffffffffffffffffffffffffffff167ffceb437c298f40d64702ac26411b2316e79f3c28ffa60edfc891ad4fc8ab82ca6000546040518082815260200191505060405180910390a2565b60008160008082825401925050819055905091905056fea264697066735822122032510ec4ba70a57be7ecbd80920213f49c97b68e3264707e93d653ff2e37064a64736f6c63430006010033000000000000000000000000000000000000000000000000000000000000000a",
            sender=addr)
        assert_equal(collateral, 408)

        tx = self.new_tx(
            sender=self.GENESIS_ADDR,
            priv_key=self.GENESIS_PRI_KEY,
            value=10 ** 20,
            receiver=addr)
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        assert_equal(self.get_balance(addr), 10 ** 20)
        assert_equal(self.get_collateral_for_storage(addr), 0)

        # if you set the storage to 6, sender will pay collateral for storage
        collateral = self.estimate_collateral(
            contract_addr=contract_addr,
            data_hex="0x60fe47b10000000000000000000000000000000000000000000000000000000000000006",
            sender=addr)
        assert_equal(collateral, 64)
        assert_equal(self.get_collateral_for_storage(addr), 0)

        # send tx to set the storage from 5 to 6
        tx = self.new_contract_tx(
            receiver=contract_addr,
            data_hex="0x60fe47b10000000000000000000000000000000000000000000000000000000000000006",
            sender=addr,
            priv_key=priv_key)
        assert_equal(self.send_tx(tx, True), tx.hash_hex())
        assert_equal(int(self.call(contract_addr, "0x6d4ce63c"), 0), 6)
        assert_equal(self.get_collateral_for_storage(addr), 10 ** 18 // 16)

        # this time you don't need to pay collateral for storage even if you change the storage value
        collateral = self.estimate_collateral(
            contract_addr=contract_addr,
            data_hex="0x60fe47b10000000000000000000000000000000000000000000000000000000000000007",
            sender=addr)
        assert_equal(collateral, 0)
        assert_equal(self.get_collateral_for_storage(addr), 10 ** 18 // 16)

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
