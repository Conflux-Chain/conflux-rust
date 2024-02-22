#!/usr/bin/env python3
from conflux.transactions import CONTRACT_DEFAULT_GAS, charged_of_huge_gas
from test_framework.contracts import ConfluxTestFrameworkForContract
from test_framework.util import assert_equal
from web3 import Web3
from web3.contract import Contract

class AdminControlTest(ConfluxTestFrameworkForContract):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1

    def run_test(self):
        pay_contract = self.cfx_contract("CheckPay")
        admin_control_contract = self.internal_contract("AdminControl")

        self.log.info("Initializing contract")
        client = self.client
        gas = CONTRACT_DEFAULT_GAS
       

        # Setup balance for node 0        
        (addr, priv_key) = client.rand_account()
        self.log.info("addr=%s priv_key=%s", addr, priv_key)
        self.cfx_transfer(addr, value = 5)
        assert_equal(client.get_balance(addr), 5000000000000000000)
        

        (addr2, priv_key2) = client.rand_account()
        self.log.info("addr2=%s priv_key2=%s", addr2, priv_key2)
        self.cfx_transfer(addr2, value = 5)
        assert_equal(client.get_balance(addr2), 5000000000000000000)

        # deploy pay contract
        pay_contract: Contract = self.cfx_contract("CheckPay").deploy(transact_args=dict(priv_key=priv_key, storage_limit=512, gas=gas))
        contract_addr = pay_contract.address
        self.log.info("contract_addr={}".format(pay_contract.address))
        assert_equal(client.get_collateral_for_storage(addr), 512 * 976562500000000)
        assert_equal(client.get_balance(contract_addr), 0)
        

        # deposit 10**18
        b0 = client.get_balance(addr)
        pay_contract.functions.recharge().cfx_transact(priv_key=priv_key, value = 1, gas=gas)
        assert_equal(client.get_balance(contract_addr), 10 ** 18)
        assert_equal(client.get_balance(addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))
        assert_equal(client.get_admin(contract_addr), addr.lower())
        

        # transfer admin (fail)
        admin_control_contract.functions.setAdmin(contract_addr, addr2).cfx_transact(priv_key=priv_key2, gas=gas)
        assert_equal(client.get_admin(contract_addr), addr.lower())
        assert_equal(client.get_balance(addr2), 5 * 10 ** 18 - charged_of_huge_gas(gas))

        # transfer admin (success)
        admin_control_contract.functions.setAdmin(contract_addr, addr2).cfx_transact(priv_key=priv_key, gas=gas)
        assert_equal(client.get_admin(contract_addr), addr2.lower())

        # destroy
        b0 = client.get_balance(addr)
        admin_control_contract.functions.destroy(contract_addr).cfx_transact(priv_key=priv_key2, gas=gas)
        assert_equal(client.get_balance(contract_addr), 0)
        assert_equal(client.get_balance(addr2), 6 * 10 ** 18 - charged_of_huge_gas(gas) * 2)
        assert_equal(client.get_collateral_for_storage(addr), 0)
        assert_equal(client.get_balance(addr), b0 + 512 * 976562500000000)

        self.log.info("Pass")

if __name__ == "__main__":
    AdminControlTest().main()
