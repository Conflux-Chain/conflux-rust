#!/usr/bin/env python3

from base import Web3Base
from conflux.config import default_config
from test_framework.util import *
from web3 import Web3

toHex = Web3.toHex

class RpcErrorTest(Web3Base):
    def set_test_params(self):
        super().set_test_params()
        self.conf_parameters["public_evm_rpc_apis"] = "\"eth\""

    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')

        self.cross_space_transfer(self.evmAccount.address, 100 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(100 * 10 ** 18))

        self.invalid_chain_id()
        self.valid_tx()
        self.gas_too_low()
        self.gas_too_high()
        self.nonce_too_low()
        self.nonce_too_high()
        self.same_nonce_higher_gas_price_required()
        self.zero_gas_price()

    def invalid_chain_id(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 21000,
            "nonce": nonce,
            "chainId": 100,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        except Exception as e:
            assert_equal(str(e), "{'code': -32000, 'message': 'invalid chain ID'}")
            return
        
    def nonce_too_low(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 21000,
            "nonce": nonce - 1,
            "chainId": 10,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        except Exception as e:
            assert_equal(str(e), "{'code': -32003, 'message': 'nonce too low'}")
            return
    
    def nonce_too_high(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 21000,
            "nonce": nonce + 2000,
            "chainId": 10,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        except Exception as e:
            assert_equal(str(e), "{'code': -32003, 'message': 'nonce too high'}")
            return
        
    def same_nonce_higher_gas_price_required(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 21000,
            "nonce": nonce,
            "chainId": 10,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
            wait_ms(1000)
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        except Exception as e:
            assert_equal(str(e), "{'code': -32603, 'message': 'replacement transaction underpriced'}")
            return
        
    def zero_gas_price(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 0,
            "gas": 21000,
            "nonce": nonce,
            "chainId": 10,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        except Exception as e:
            assert_equal(str(e), "{'code': -32603, 'message': 'transaction underpriced'}")
            return
        
    def gas_too_low(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 2100,
            "nonce": nonce,
            "chainId": 10,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        except Exception as e:
            assert_equal(str(e), "{'code': -32000, 'message': 'intrinsic gas too low'}")
            return
    
    # TODO: estimate: out of gas

    def gas_too_high(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 40000000,
            "nonce": nonce,
            "chainId": 10,
        })

        try:
            self.w3.eth.send_raw_transaction(signed["rawTransaction"])
            # AssertionError("send tx failed")
        except Exception as e:
            assert_equal(str(e), "{'code': -32603, 'message': 'exceeds block gas limit'}")
            return
        
    def valid_tx(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "maxFeePerGas": 1,
            "maxPriorityFeePerGas": 1,
            "gas": 21000,
            "nonce": nonce,
            "chainId": 10,
        })

        tx_hash = self.w3.eth.send_raw_transaction(signed["rawTransaction"])
        self.rpc.generate_blocks(20, 1)

        next_nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        assert_equal(next_nonce, nonce + 1)

        tx = self.w3.eth.getTransaction(tx_hash)
        assert_equal(tx["nonce"], nonce)
        assert_equal(tx["type"], "0x2")


def wait_ms(ms):
    time.sleep(ms / 1000)

if __name__ == "__main__":
    RpcErrorTest().main()