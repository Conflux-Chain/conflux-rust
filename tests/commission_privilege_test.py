#!/usr/bin/env python3
from conflux.transactions import CONTRACT_DEFAULT_GAS, COLLATERAL_UNIT_IN_DRIP, charged_of_huge_gas
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class CommissionPrivilegeTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        self.w3 = self.cw3
        self.sponsorControl = self.internal_contract(name="SponsorWhitelistControl")
        bytes_per_key = 64
        collateral_per_storage_key = COLLATERAL_UNIT_IN_DRIP * 64
        # change upper tx gas limit to (GENESIS_GAS_LIMIT/2 - 1); -1 because below gas is set to upper_bound + 1
        tx_gas_upper_bound = int(default_config["GENESIS_GAS_LIMIT"] / 2 - 1)  # type: ignore

        self.log.info("Initializing contract")
        genesis_addr = self.core_accounts[0].hex_address
        self.log.info("genesis_addr={}".format(genesis_addr))
        gas_price = 1
        gas = CONTRACT_DEFAULT_GAS
        self.start_block_gen()

        client = self.client
        (addr1, priv_key1) = client.rand_account()
        (addr2, priv_key2) = client.rand_account()
        (addr3, priv_key3) = client.rand_account()
        (addr4, priv_key4) = client.rand_account()
        self.w3.wallet.add_account(priv_key1)
        self.w3.wallet.add_account(priv_key2)
        self.w3.wallet.add_account(priv_key3)
        self.w3.wallet.add_account(priv_key4)
        self.cfx_transfer(addr1, value = 1)
        assert_equal(client.get_balance(addr1), 10 ** 18)

        self.cfx_transfer(addr2, value = 1)
        assert_equal(client.get_balance(addr2), 10 ** 18)

        self.cfx_transfer(addr3, value = 3)
        assert_equal(client.get_balance(addr3), 3 * 10 ** 18)

        # setup contract
        before_setup_collateral = client.get_collateral_for_storage(genesis_addr)
        test_contract = self.deploy_contract("CommissionPrivilegeTest")
        after_setup_collateral = client.get_collateral_for_storage(genesis_addr)
        contract_addr = test_contract.address.hex_address
        assert_equal(client.get_balance(contract_addr), 0)
        assert_equal(after_setup_collateral - before_setup_collateral, 1024 * COLLATERAL_UNIT_IN_DRIP)

        # sponsor the contract failed due to sponsor_balance < 1000 * upper_bound
        b0 = client.get_balance(genesis_addr)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 0)

        assert_tx_exec_error(client, self.sponsorControl.functions.setSponsorForGas(contract_addr, tx_gas_upper_bound).transact({
                "value": tx_gas_upper_bound * 1000 - 1,
                "gas": gas,
                "storageLimit": 0,
                "gasPrice": 1,
            }).to_0x_hex(),
            'VmError(InternalContract("sponsor should at least sponsor upper_bound * 1000"))'
        )

        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 0)
        assert_equal(client.get_sponsor_for_gas(contract_addr), ZERO_ADDRESS)
        assert_equal(client.get_sponsor_gas_bound(contract_addr), 0)
        assert_equal(client.get_balance(genesis_addr), b0 - gas)

        # sponsor the contract succeed
        b0 = client.get_balance(genesis_addr)
        self.sponsorControl.functions.setSponsorForGas(contract_addr, tx_gas_upper_bound).transact({
            "value": 10**18,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr.lower())
        assert_equal(client.get_sponsor_gas_bound(contract_addr), tx_gas_upper_bound)
        assert_equal(client.get_balance(genesis_addr), b0 - 10 ** 18 - charged_of_huge_gas(gas))

        check_info = client.check_balance_against_transaction(addr1, contract_addr, gas, gas_price, storage_limit=0)
        assert_equal(check_info['willPayTxFee'], True)
        assert_equal(check_info['willPayCollateral'], True)
        assert_equal(check_info['isBalanceEnough'], True)

        check_info = client.check_balance_against_transaction(addr4, contract_addr, gas, gas_price, storage_limit=0)
        assert_equal(check_info['willPayTxFee'], True)
        assert_equal(check_info['willPayCollateral'], True)
        assert_equal(check_info['isBalanceEnough'], False)

        # set privilege for addr4
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.add(addr4).transact({
            "storageLimit": 64,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key) 

        check_info = client.check_balance_against_transaction(addr4, contract_addr, gas, gas_price, storage_limit=0)
        assert_equal(check_info['willPayTxFee'], False)
        assert_equal(check_info['willPayCollateral'], True)
        assert_equal(check_info['isBalanceEnough'], True)

        # remove privilege for addr4
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.remove(addr4).transact({
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 - collateral_per_storage_key)
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) + collateral_per_storage_key)

        # set privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.add(addr1).transact({
            "storageLimit": 64,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)

        # addr1 call contract with privilege
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        test_contract.functions.foo().transact({
            "from": self.cfx.address(addr1),
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_balance(addr1), b1)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))

        # addr1 call contract with privilege and large tx fee
        b1 = client.get_balance(addr1)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        test_contract.functions.foo().transact({
            "from": self.cfx.address(addr1),
            "gas": tx_gas_upper_bound+1,
            "storageLimit": 0,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_balance(addr1), b1 - charged_of_huge_gas(tx_gas_upper_bound + 1))
        
        # addr2 call contract without privilege
        b2 = client.get_balance(addr2)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        test_contract.functions.foo().transact({
            "from": self.cfx.address(addr2),
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_balance(addr2), b2 - charged_of_huge_gas(gas))

        # set privilege for addr2
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.add(addr2).transact({
            "storageLimit": 64,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - collateral_per_storage_key)
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + collateral_per_storage_key)

        # now, addr2 call contract with privilege
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        test_contract.functions.foo().transact({
            "from": self.cfx.address(addr2),
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb - charged_of_huge_gas(gas))
        assert_equal(client.get_balance(addr2), b2)

        # remove privilege for addr1
        b0 = client.get_balance(genesis_addr)
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.remove(addr1).transact({
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 - collateral_per_storage_key)
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) + collateral_per_storage_key)

        # addr1 call contract without privilege
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        b1 = client.get_balance(addr1)
        test_contract.functions.foo().transact({
            "from": self.cfx.address(addr1),
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_balance(addr1), b1 - charged_of_huge_gas(gas))

        # new sponsor failed due to small sponsor_balance
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        assert_tx_exec_error(client, self.sponsorControl.functions.setSponsorForGas(contract_addr, tx_gas_upper_bound).transact({
                "value": int(0.5 * 10**18),
                "storageLimit": 0,
                "from": self.cfx.address(addr3),
                "gas": gas,
                "gasPrice": 1,
            }).to_0x_hex(),
            'VmError(InternalContract("sponsor_balance is not exceed previous sponsor"))'
        )
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr.lower())
        assert_equal(client.get_balance(addr3), b3 - gas)

        # new sponsor failed due to small upper bound
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        assert_tx_exec_error(
            client,
            self.sponsorControl.functions.setSponsorForGas(contract_addr, tx_gas_upper_bound - 1).transact({
                "value": 10**18,
                "storageLimit": 0,
                "gas": gas,
                "gasPrice": 1,
                "from": self.cfx.address(addr3),
            }).to_0x_hex(),
            'VmError(InternalContract("upper_bound is not exceed previous sponsor"))'
        )
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sb)
        assert_equal(client.get_sponsor_for_gas(contract_addr), genesis_addr.lower())
        assert_equal(client.get_balance(addr3), b3 - gas)

        # new sponsor succeed
        b0 = client.get_balance(genesis_addr)
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_gas(contract_addr)
        self.sponsorControl.functions.setSponsorForGas(contract_addr, tx_gas_upper_bound + 1).transact({
            "value": 10**18,
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
            "from": self.cfx.address(addr3),
        }).executed()
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), 10 ** 18)
        assert_equal(client.get_sponsor_gas_bound(contract_addr), tx_gas_upper_bound + 1)
        assert_equal(client.get_sponsor_for_gas(contract_addr), addr3.lower())
        assert_equal(client.get_balance(addr3), b3 - 10 ** 18 - charged_of_huge_gas(gas))
        assert_equal(client.get_balance(genesis_addr), b0 + sb)

        # sponsor the contract for collateral failed due to zero sponsor balance
        b3 = client.get_balance(addr3)
        assert_tx_exec_error(
            client,
            self.sponsorControl.functions.setSponsorForCollateral(contract_addr).transact({
                "value": 0,
                "storageLimit": 0,
                "gas": gas,
                "gasPrice": 1,
                "from": self.cfx.address(addr3),
            }).to_0x_hex(),
            'VmError(InternalContract("zero sponsor balance is not allowed"))'
        )
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 0)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), ZERO_ADDRESS)
        assert_equal(client.get_balance(addr3), b3 - gas)

        # sponsor the contract for collateral succeed
        b3 = client.get_balance(addr3)
        self.sponsorControl.functions.setSponsorForCollateral(contract_addr).transact({
            "value": 10 ** 18 - 1,
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
            "from": self.cfx.address(addr3),
        }).executed()
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), 10 ** 18 - 1)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), addr3.lower())
        assert_equal(client.get_balance(addr3), b3 - charged_of_huge_gas(gas) - 10 ** 18 + 1)

        check_info = client.check_balance_against_transaction(addr1, contract_addr, gas, gas_price, storage_limit=0)
        assert_equal(check_info['willPayTxFee'], True)
        assert_equal(check_info['willPayCollateral'], True)
        assert_equal(check_info['isBalanceEnough'], True)

        # addr1 create 2 keys without privilege, and storage limit is 1, should failed
        b1 = client.get_balance(addr1)
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), 0)
        assert_tx_exec_error(
            client,
            test_contract.functions.par_add(0,2).transact({
                "from": self.cfx.address(addr1),
                "storageLimit": bytes_per_key,
                "gas": gas,
                "gasPrice": 1,
            }).to_0x_hex(),
            "VmError(ExceedStorageLimit)"
        )
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), 0)
        assert_equal(client.get_balance(addr1), b1 - gas)

        # addr1 create 2 keys without privilege, and storage limit is 2, should succeed
        b1 = client.get_balance(addr1)
        test_contract.functions.par_add(0,2).transact({
            "from": self.cfx.address(addr1),
            "storageLimit": bytes_per_key * 2,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), collateral_per_storage_key * 2)
        assert_equal(client.get_balance(addr1), b1 - charged_of_huge_gas(gas) - collateral_per_storage_key * 2)

        # remove 1 key create by addr1
        b1 = client.get_balance(addr1)
        test_contract.functions.par_del(0,1).transact({
            "from": self.cfx.address(addr1),
            "storageLimit": bytes_per_key * 2,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), 0)
        assert_equal(client.get_collateral_for_storage(addr1), collateral_per_storage_key)
        assert_equal(client.get_balance(addr1), b1 - charged_of_huge_gas(gas) + collateral_per_storage_key)

        check_info = client.check_balance_against_transaction(addr2, contract_addr, gas, gas_price, storage_limit=bytes_per_key)
        assert_equal(check_info['willPayTxFee'], False)
        assert_equal(check_info['willPayCollateral'], False)
        assert_equal(check_info['isBalanceEnough'], True)

        check_info = client.check_balance_against_transaction(addr2, contract_addr, gas, gas_price, storage_limit=10 ** 18)
        assert_equal(check_info['willPayTxFee'], False)
        assert_equal(check_info['willPayCollateral'], True)
        assert_equal(check_info['isBalanceEnough'], False)

        # addr2 create 2 keys with privilege, and storage limit is 1, should succeed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        test_contract.functions.par_add(2,4).transact({
            "from": self.cfx.address(addr2),
            "storageLimit": bytes_per_key,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 2)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc - collateral_per_storage_key * 2)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - charged_of_huge_gas(gas))
        assert_equal(client.get_collateral_for_storage(addr2), 0)
        assert_equal(client.get_balance(addr2), b2)

        # addr2 create 13 keys with privilege, and storage limit is 0, should succeed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        test_contract.functions.par_add(4,17).transact({
            "from": self.cfx.address(addr2),
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 15)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc - collateral_per_storage_key * 13)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - charged_of_huge_gas(gas))
        assert_equal(client.get_collateral_for_storage(addr2), 0)
        assert_equal(client.get_balance(addr2), b2)

        # now sponsor_balance is unable to pay collateral for storage
        # the balance of addr2 is able to pay 15 collateral for storage, but not 16
        assert_greater_than(collateral_per_storage_key, client.get_sponsor_balance_for_collateral(contract_addr))
        assert_greater_than(collateral_per_storage_key * 16, client.get_balance(addr2))
        assert_greater_than(client.get_balance(addr2), collateral_per_storage_key * 15)

        # addr2 create 1 keys with privilege, and storage limit is 0, should failed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        assert_tx_exec_error(
            client,
            test_contract.functions.par_add(17,18).transact({
                "from": self.cfx.address(addr2),
                "storageLimit": 0,
                "gas": gas,
                "gasPrice": 1,
            }).to_0x_hex(),
            "VmError(NotEnoughBalanceForStorage { required: 62500000000000000, got: 62499999999999999 })"
        )
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 15)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - gas)
        assert_equal(client.get_collateral_for_storage(addr2), 0)
        assert_equal(client.get_balance(addr2), b2)

        # addr2 create 1 keys with privilege, and storage limit is 2, should succeed
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        test_contract.functions.par_add(17, 18).transact({
            "from": self.cfx.address(addr2),
            "storageLimit": bytes_per_key * 2,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 15)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - charged_of_huge_gas(gas))
        assert_equal(client.get_collateral_for_storage(addr2), collateral_per_storage_key)
        assert_equal(client.get_balance(addr2), b2 - collateral_per_storage_key)

        # addr2 del 10 keys with privilege
        sbc = client.get_sponsor_balance_for_collateral(contract_addr)
        sbg = client.get_sponsor_balance_for_gas(contract_addr)
        b2 = client.get_balance(addr2)
        test_contract.functions.par_del(2,12).transact({
            "from": self.cfx.address(addr2),
            "storageLimit": bytes_per_key,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), collateral_per_storage_key * 5)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sbc + collateral_per_storage_key * 10)
        assert_equal(client.get_sponsor_balance_for_gas(contract_addr), sbg - charged_of_huge_gas(gas))
        assert_equal(client.get_collateral_for_storage(addr2), collateral_per_storage_key)
        assert_equal(client.get_balance(addr2), b2)

        # addr3 sponsor more, treat as transfer
        b3 = client.get_balance(addr3)
        sb = client.get_sponsor_balance_for_collateral(contract_addr)
        self.sponsorControl.functions.setSponsorForCollateral(contract_addr).transact({
            "value": sb,
            "storageLimit": 0,
            "from": self.cfx.address(addr3),
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sb * 2)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), addr3.lower())
        assert_equal(client.get_balance(addr3), b3 - charged_of_huge_gas(gas) - sb)

        # genesis sponsor with sponsor balance, should failed
        b0 = client.get_balance(genesis_addr)
        sb = client.get_sponsor_balance_for_collateral(contract_addr)
        err_msg = 'VmError(InternalContract("sponsor_balance is not enough to cover previous sponsor\'s sponsor_balance and collateral_for_storage"))'
        assert_tx_exec_error(
            client,
            self.sponsorControl.functions.setSponsorForCollateral(contract_addr).transact({
                "value": sb + 1,
                "storageLimit": 0,
                "gas": gas,
                "gasPrice": 1,
            }).to_0x_hex(),
            err_msg
        )
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sb)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), addr3.lower())
        assert_equal(client.get_balance(genesis_addr), b0 - gas)

        # genesis sponsor with sponsor balance and collateral_for_storage, should succeed
        b0 = client.get_balance(genesis_addr)
        b3 = client.get_balance(addr3)
        cfs = client.get_collateral_for_storage(contract_addr)
        sb = client.get_sponsor_balance_for_collateral(contract_addr)
        self.sponsorControl.functions.setSponsorForCollateral(contract_addr).transact({
            "value": sb + cfs + 1,
            "storageLimit": 0,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(contract_addr), cfs)
        assert_equal(client.get_sponsor_balance_for_collateral(contract_addr), sb + 1)
        assert_equal(client.get_sponsor_for_collateral(contract_addr), genesis_addr.lower())
        assert_equal(client.get_balance(genesis_addr), b0 - charged_of_huge_gas(gas) - sb - cfs - 1)
        assert_equal(client.get_balance(addr3), b3 + sb + cfs)
        

        # storage change test
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.par(10,20,30,41).transact({
            "storageLimit": bytes_per_key * 30,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + 11 * collateral_per_storage_key)
        

        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.par_add_del(110,120,110,120).transact({
            "storageLimit": bytes_per_key * 30,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + 10 * collateral_per_storage_key)
        

        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.par_add_del(210,220,215,220).transact({
            "storageLimit": bytes_per_key * 30,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + 5 * collateral_per_storage_key)

        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.par_add_del(310,320,320,330).transact({
            "storageLimit": bytes_per_key * 30,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + 10 * collateral_per_storage_key)

        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.par_add_del(410, 420, 409, 430).transact({
            "storageLimit": bytes_per_key * 300,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + 21 * collateral_per_storage_key)

        # test recurrence
        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.rec(510, 520, 3).transact({
            "storageLimit": bytes_per_key * 30,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 + 4 * collateral_per_storage_key)

        c0 = client.get_collateral_for_storage(genesis_addr)
        test_contract.functions.par_del(510, 520).transact({
            "storageLimit": bytes_per_key * 30,
            "gas": gas,
            "gasPrice": 1,
        }).executed()
        assert_equal(client.get_collateral_for_storage(genesis_addr), c0 - 4 * collateral_per_storage_key)

        self.log.info("Pass")


if __name__ == "__main__":
    CommissionPrivilegeTest().main()
