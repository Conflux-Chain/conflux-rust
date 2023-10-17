#!/usr/bin/env python3
from eth_utils import decode_hex

from conflux.address import hex_to_b32_address
from conflux.rpc import RpcClient, get_contract_function_data
from conflux.transactions import CONTRACT_DEFAULT_GAS, COLLATERAL_UNIT_IN_DRIP, charged_of_huge_gas
from conflux.utils import priv_to_addr
from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x, wait_for_initial_nonce_for_address
from test_framework.contracts import ConfluxTestFrameworkForContract
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3
from web3.contract import Contract

class SponsoredTxTest(ConfluxTestFrameworkForContract):
    def __init__(self):
        super().__init__()

        self.nonce_map = {}
        self.genesis_priv_key = default_config['GENESIS_PRI_KEY']
        self.genesis_addr = priv_to_addr(self.genesis_priv_key)
        self.balance_map = {self.genesis_priv_key: default_config['TOTAL_COIN']}

    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 1

    def run_test(self):
        collateral_per_storage_key = COLLATERAL_UNIT_IN_DRIP * 64
        upper_bound = 5 * 10 ** 7
        gas = CONTRACT_DEFAULT_GAS

        self.log.info("Initializing contract")

        control_contract = self.internal_contract("SponsorWhitelistControl")
        test_contract = self.cfx_contract("CommissionPrivilegeTest")

        client = self.client
        genesis_addr = self.genesis_addr


        # Setup balance for node 0
        (addr1, priv_key1) = client.rand_account()
        self.log.info("addr1={}".format(addr1))
        self.cfx_transfer(addr1, 10 ** 6, decimals=0)
        assert_equal(client.get_balance(addr1), 10 ** 6)

        # setup contract
        test_contract: Contract = test_contract.deploy()
        contract_addr = test_contract.address
        self.log.info("contract_addr={}".format(test_contract.address))
        assert_equal(client.get_balance(contract_addr), 0)


        # sponsor the contract succeed
        b0 = client.get_balance(genesis_addr)
        control_contract.functions.setSponsorForGas(contract_addr, upper_bound).cfx_transact(value = 1, gas = gas)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr.lower())
        assert_equal(client.get_sponsor_gas_bound(contract_addr), upper_bound)
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))

        # set privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        receipt = test_contract.functions.add(addr1).cfx_transact(storage_limit = 64, gas = gas)
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)
        assert_equal(receipt['gasCoveredBySponsor'], False)


        # addr1 call contract with privilege without enough cfx for gas fee
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        receipt = test_contract.functions.foo().cfx_transact(priv_key = priv_key1, storage_limit = 0, gas = gas)
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(receipt['gasCoveredBySponsor'], True)


        # sponsor collateral for the contract succeed
        b0 = client.get_balance(genesis_addr)
        control_contract.functions.setSponsorForCollateral(contract_addr).cfx_transact(value = 1, gas = gas)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), genesis_addr.lower())
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))


        # addr1 call contract with privilege without enough cfx for storage
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        receipt = test_contract.functions.foo().cfx_transact(priv_key = priv_key1, storage_limit = 1024, gas = gas)
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(receipt['storageCoveredBySponsor'], True)

        # addr1 call with larger storage limit, should be rejected for not enough balance
        data = test_contract.functions.foo().data()
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
