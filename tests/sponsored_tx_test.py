#!/usr/bin/env python3
from cfx_utils import CFX
from conflux.transactions import CONTRACT_DEFAULT_GAS, COLLATERAL_UNIT_IN_DRIP, charged_of_huge_gas
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class SponsoredTxTest(ConfluxTestFramework):
    def __init__(self):
        super().__init__()

        self.nonce_map = {}
        self.genesis_priv_key = self.core_accounts[0].key
        self.genesis_addr = self.core_accounts[0].address
        self.balance_map = {self.genesis_priv_key: default_config['TOTAL_COIN']}

    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.w3 = self.cw3
        collateral_per_storage_key = COLLATERAL_UNIT_IN_DRIP * 64
        upper_bound = 5 * 10 ** 7
        gas = CONTRACT_DEFAULT_GAS

        self.log.info("Initializing contract")

        control_contract = self.internal_contract("SponsorWhitelistControl")

        client = self.client
        genesis_addr = self.genesis_addr.hex_address


        # Setup balance for node 0
        (addr1, priv_key1) = client.rand_account()
        self.log.info("addr1={}".format(addr1))
        self.cfx_transfer(addr1, 10 ** 6, decimals=0)
        assert_equal(client.get_balance(addr1), 10 ** 6)
        self.w3.wallet.add_account(priv_key1)

        # setup contract
        test_contract = self.deploy_contract("CommissionPrivilegeTest")
        contract_addr = test_contract.address.hex_address
        self.log.info("contract_addr={}".format(test_contract.address))
        assert_equal(client.get_balance(contract_addr), 0)


        # sponsor the contract succeed
        b0 = client.get_balance(genesis_addr)
        control_contract.functions.setSponsorForGas(contract_addr, upper_bound).transact({
            "value": CFX(1),
            "gas": gas,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr.lower())
        assert_equal(client.get_sponsor_gas_bound(contract_addr), upper_bound)
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))

        # set privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        receipt = test_contract.functions.add(addr1).transact({
            "storageLimit": 64,
            "gas": gas,
        }).executed()
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)
        assert_equal(receipt['gasCoveredBySponsor'], False)


        # addr1 call contract with privilege without enough cfx for gas fee
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        receipt = test_contract.functions.foo().transact({
            "storageLimit": 0,
            "gas": gas,
            "from": self.cfx.address(addr1),
        }).executed()
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(receipt['gasCoveredBySponsor'], True)


        # sponsor collateral for the contract succeed
        b0 = client.get_balance(genesis_addr)
        control_contract.functions.setSponsorForCollateral(contract_addr).transact({
            "value": 10 ** 18,
            "gas": gas,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), genesis_addr.lower())
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))


        # addr1 call contract with privilege without enough cfx for storage
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        receipt = test_contract.functions.foo().transact({
            "storageLimit": 1024,
            "gas": gas,
            "from": self.cfx.address(addr1),
        }).executed()
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(receipt['storageCoveredBySponsor'], True)

        # addr1 call with larger storage limit, should be rejected for not enough balance
        data = test_contract.functions.foo().encode_transaction_data()
        transaction = client.new_contract_tx(receiver=contract_addr, data_hex=encode_hex(data), priv_key=priv_key1,
                                             storage_limit=1025)
        # rejected for not enough balance
        assert_raises_rpc_error(None, None, client.send_tx, transaction)
        tx_info = self.nodes[0].txpool_txWithPoolInfo(transaction.hash_hex())
        assert_equal(tx_info['exist'], False)


        # send 1025 * 10 ** 18 // 1024 CFX to addr1
        receipt = self.cfx_transfer(addr1, value = 1025 * 10 ** 18 // 1024, decimals = 0)
        assert_equal(client.get_balance(addr1), 10 ** 6 + 1025 * 10 ** 18 // 1024)

        client.send_tx(transaction, True)
        assert_equal(receipt['storageCoveredBySponsor'], False)
        tx_info = self.nodes[0].txpool_txWithPoolInfo(transaction.hash_hex())
        # Now addr1 pays for storage collateral by itself.
        assert_equal(int(tx_info['local_nonce'], 16), 3)
        assert_equal(tx_info['packed'], True)

        self.log.info("Pass")


if __name__ == "__main__":
    SponsoredTxTest().main()
