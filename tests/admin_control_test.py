#!/usr/bin/env python3
from cfx_utils import CFX, Drip
from conflux.transactions import CONTRACT_DEFAULT_GAS, charged_of_huge_gas
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal

class AdminControlTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.w3 = self.cw3
        pay_contract = self.cfx_contract("CheckPay")
        admin_control_contract = self.internal_contract("AdminControl")

        self.log.info("Initializing contract")
        gas = CONTRACT_DEFAULT_GAS

        # Setup balance for node 0  
        acct1 = self.cfx.account.create()
        self.log.info("addr=%s priv_key=%s", acct1.address, acct1.key.hex())
        self.cfx_transfer(acct1.hex_address, value = 5)
        assert_equal(self.cfx.get_balance(acct1.address).to("CFX"), CFX(5))
        self.w3.wallet.add_account(acct1)
        

        acct2 = self.cfx.account.create()
        self.log.info("addr2=%s priv_key2=%s", acct2.address, acct2.key.hex())
        self.cfx_transfer(acct2.hex_address, value = 5)
        assert_equal(self.cfx.get_balance(acct2.address).to("CFX"), CFX(5))
        self.w3.wallet.add_account(acct2)

        # deploy pay contract
        pay_contract = self.deploy_contract(name="CheckPay", transact_args={
            "from": acct1.address,
            "storageLimit": 512,
            "gas": gas,
            "gasPrice": 1
        })
        contract_addr = pay_contract.address
        self.log.info("contract_addr={}".format(pay_contract.address))
        assert_equal(self.cfx.get_collateral_for_storage(acct1.address), 512 * 976562500000000)
        assert_equal(self.cfx.get_balance(contract_addr), 0)
        

        # deposit 10**18
        b0 = self.cfx.get_balance(acct1.address)
        pay_contract.functions.recharge().transact({
            "from": acct1.address,
            "value": CFX(1),
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(self.cfx.get_balance(contract_addr), CFX(1))
        assert_equal(self.cfx.get_balance(acct1.address), b0 - CFX(1) - Drip(charged_of_huge_gas(gas)))
        assert_equal(self.cfx.get_admin(contract_addr), acct1.address.lower())
        

        # transfer admin (fail)
        admin_control_contract.functions.setAdmin(contract_addr, acct2.address).transact({
            "from": acct2.address,
            "gas": gas,
            "gasPrice": 1
        }).executed()
        assert_equal(self.cfx.get_admin(contract_addr), acct1.address.lower())
        assert_equal(self.cfx.get_balance(acct2.address), CFX(5) - Drip(charged_of_huge_gas(gas)))

        # transfer admin (success)
        admin_control_contract.functions.setAdmin(contract_addr, acct2.address).transact({
            "from": acct1.address,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(self.cfx.get_admin(contract_addr), acct2.address.lower())

        # destroy
        b0 = self.cfx.get_balance(acct1.address)
        admin_control_contract.functions.destroy(contract_addr).transact({
            "from": acct2.address,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(self.cfx.get_balance(contract_addr), 0)
        assert_equal(self.cfx.get_balance(acct2.address), CFX(6) - Drip(charged_of_huge_gas(gas) * 2))
        assert_equal(self.cfx.get_collateral_for_storage(acct1.address), 0)
        assert_equal(self.cfx.get_balance(acct1.address), b0 + Drip(512 * 976562500000000))

        self.log.info("Pass")

if __name__ == "__main__":
    AdminControlTest().main()
