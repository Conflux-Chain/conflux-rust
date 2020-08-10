#!/usr/bin/env python3
import os
import eth_utils
import time

from http.client import CannotSendRequest
from eth_utils import decode_hex

from test_framework.block_gen_thread import BlockGenThread
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.blocktools import create_transaction, encode_hex_0x
from test_framework.util import *
from test_framework.smart_contract_bench_base import SmartContractBenchBase
from conflux.config import default_config
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.transactions import CONTRACT_DEFAULT_GAS, charged_of_huge_gas
from conflux.utils import sha3 as keccak
from conflux.utils import encode_hex, priv_to_addr, parse_as_int

from web3 import Web3

class ContractBenchTest(SmartContractBenchBase):
    def set_test_params(self):
        self.num_nodes = 1
        self.collateral_per_byte = 10 ** 18 // 1024

    def setup_network(self):
        self.setup_nodes()

    def testEventContract(self):
        CONTRACT_PATH = "contracts/event_bytecode_new.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)
        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_PATH)
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read().strip()
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, bytecode, storage_limit=1047)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 1)

        # construct contract object 
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/event_abi_new.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        self.tx_conf["to"] = contractAddr

        # interact with foo()
        data = contract.functions.foo().buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 2)
        assert_equal(logs[-1]["topics"][1], self.address_to_topic(self.sender))
        assert_equal(logs[-1]["topics"][2], self.number_to_topic(1))


        # interact with goo(10), will pass modifier, emit new event
        data = contract.functions.goo(10).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 3)
        assert_equal(logs[-1]["topics"][1], self.address_to_topic(self.sender))
        assert_equal(logs[-1]["topics"][2], self.number_to_topic(11))

        # interact with goo(10), will not pass modifier, no event emitted
        data = contract.functions.goo(10).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 3)

        # call const function hoo()
        data = contract.functions.hoo().buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.number_to_topic(11))

        # call const function byte32oo(solution)
        data = contract.functions.byte32oo(self.solution).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.solution)

        # call const function getSha256(solution)
        data = contract.functions.getSha256(self.solution).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.problem)

    def testBallotContract(self):
        CONTRACT_PATH = "contracts/ballot_bytecode.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/ballot_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )

        # deploy contract
        data = contract.constructor(10).buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=2127)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr

        # interact with vote()
        data = contract.functions.vote(5).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64 * 2)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 1)
        assert_equal(logs[-1]["data"], self.number_to_topic(5))

        # call const function winningProposal()
        data = contract.functions.winningProposal().buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.number_to_topic(5))

    def testHTLCContract(self):
        CONTRACT_PATH = "contracts/htlc_bytecode_new.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/htlc_abi_new.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )

        # deploy contract
        data = contract.constructor().buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=4785)
        tx_hash = receipt['transactionHash']
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 1)
        assert_equal(logs[-1]["topics"][1], self.address_to_topic(self.sender))
        assert_equal(logs[-1]["topics"][2], self.number_to_topic(16))

        # call getNow()
        data = contract.functions.getNow().buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) - int(time.time()) < 5)

        b0 = self.rpc.get_balance(self.sender)
        c0 = self.rpc.get_collateral_for_storage(self.sender)
        gas = CONTRACT_DEFAULT_GAS
        # interact with newContract(), sender send conflux to himself
        time_lock = int(time.time()) + 7200
        data = contract.functions.newContract(self.sender_checksum, self.problem, time_lock).buildTransaction(self.tx_conf)["data"];
        cost = 5000000000000000000
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, cost, storage_limit=320, gas=gas)
        logs = self.rpc.get_logs(self.filter)
        c1 = self.rpc.get_collateral_for_storage(self.sender)
        assert_equal(len(logs), l + 2)
        assert_equal(self.rpc.get_balance(contractAddr), cost)
        assert_equal(self.rpc.get_balance(self.sender), b0 - cost - charged_of_huge_gas(gas) - (c1 - c0))
        contract_id = logs[-1]["topics"][1]

        # call getContract
        cid0 = contract_id
        data = contract.functions.getContract(contract_id).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        result = result[2:]
        res = ['0x'+result[i * 64 : (i + 1) * 64] for i in range(8)]
        assert_equal(res[0][-20:], self.sender[-20:])
        assert_equal(res[1][-20:], self.sender[-20:])
        assert_equal(int(res[2], 0), cost)
        assert_equal(res[3], self.problem)
        assert_equal(int(res[4], 0), time_lock)
        assert_equal(int(res[5], 0), 0)
        assert_equal(int(res[6], 0), 0)
        assert_equal(int(res[7], 0), 0)

        # interact with withdraw()
        data = contract.functions.withdraw(contract_id, self.solution).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=128)
        assert_equal(self.rpc.get_balance(contractAddr), 0)
        c2 = self.rpc.get_collateral_for_storage(self.sender)
        assert_equal(c2 - c1, 125000000000000000)
        assert_equal(self.rpc.get_balance(self.sender), b0 - charged_of_huge_gas(gas) * 2 - (c2 - c0))
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 3)

        # call getContract
        data = contract.functions.getContract(contract_id).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        result = result[2:]
        res = ['0x'+result[i * 64 : (i + 1) * 64] for i in range(8)]
        assert_equal(res[0][-20:], self.sender[-20:])
        assert_equal(res[1][-20:], self.sender[-20:])
        assert_equal(int(res[2], 0), cost)
        assert_equal(res[3], self.problem)
        assert_equal(int(res[4], 0), time_lock)
        assert_equal(int(res[5], 0), 1)
        assert_equal(int(res[6], 0), 0)
        assert_equal(res[7], self.solution)
        receipt = self.rpc.get_transaction_receipt(tx_hash)

    def testPayContract(self):
        CONTRACT_PATH = "contracts/pay_bytecode.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/pay_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )

        # deploy contract
        data = contract.constructor().buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=517)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        b0 = self.rpc.get_balance(self.sender)
        # interact with recharge()
        data = contract.functions.recharge().buildTransaction(self.tx_conf)["data"]
        cost = 5000000000000000000
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, cost)
        b1 = self.rpc.get_balance(self.sender)
        bc = self.rpc.get_balance(contractAddr)
        assert_equal(bc, cost)

        #interact with withdraw
        data = contract.functions.withdraw(self.sender_checksum).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, 0)
        b2 = self.rpc.get_balance(self.sender)
        bc = self.rpc.get_balance(contractAddr)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(bc, 0)

    def testMappingContract(self):
        CONTRACT_PATH = "contracts/mapping_bytecode.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/mapping_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )

        # deploy contract
        data = contract.constructor(1).buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=2287)
        tx_hash = receipt['transactionHash']
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr

        c = "0x81f3521d71990945b99e1c592750d7157f2b545f"
        def check_wards(x, y, z):
          data = contract.functions.wards(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
          result = self.rpc.call(contractAddr, data)
          A = int(result, 0)
          assert(A == x)
          data = contract.functions.wards(self.sender_checksum).buildTransaction(self.tx_conf)["data"]
          result = self.rpc.call(contractAddr, data)
          B = int(result, 0)
          assert(B == y)
          data = contract.functions.wards(Web3.toChecksumAddress(c)).buildTransaction(self.tx_conf)["data"]
          result = self.rpc.call(contractAddr, data)
          C = int(result, 0)
          assert(C == z)

        # deny pub[0]
        check_wards(0, 2, 0)
        data = contract.functions.set1(Web3.toChecksumAddress(c)).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64)
        check_wards(0, 2, 1)
        data = contract.functions.set2(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64)
        check_wards(2, 2, 1)
        data = contract.functions.set0(Web3.toChecksumAddress(c)).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64)
        check_wards(2, 2, 0)
        data = contract.functions.set0(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64)
        check_wards(0, 2, 0)


    def testDaiContract(self):
        CONTRACT_PATH = "contracts/Dai_bytecode.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/Dai_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )

        # deploy contract
        data = contract.constructor(1).buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=8239)
        tx_hash = receipt['transactionHash']
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr

        # rely [0,5)
        for i in range(5):
          data = contract.functions.rely(Web3.toChecksumAddress(self.pub[i])).buildTransaction(self.tx_conf)["data"]
          result = self.call_contract(self.sender, self.priv_key, contractAddr, data, 0, storage_limit=64)
          assert_equal(result["outcomeStatus"], "0x0")

        # deny 1, 3
        for i in range(5):
          if (i % 2 == 1):
            data = contract.functions.deny(Web3.toChecksumAddress(self.pub[i])).buildTransaction(self.tx_conf)["data"]
            result = self.call_contract(self.pub[i - 1], self.pri[i - 1], contractAddr, data, 0)
            assert_equal(result["outcomeStatus"], "0x0")

        # check wards
        for i in range(5):
          data = contract.functions.wards(Web3.toChecksumAddress(self.pub[i])).buildTransaction(self.tx_conf)["data"]
          result = self.rpc.call(contractAddr, data)
          assert_equal(int(result, 0), int(i % 2 == 0))

        # mint tokens
        data = contract.functions.mint(Web3.toChecksumAddress(self.pub[0]), 100000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, 0, storage_limit=128)
        logs = self.rpc.get_logs(self.filter)

        # check balance
        data = contract.functions.balanceOf(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) == 100000)

        # approve
        data = contract.functions.approve(self.sender_checksum, 50000).buildTransaction(self.tx_conf)["data"]
        result= self.call_contract(self.pub[0], self.pri[0], contractAddr, data, storage_limit=64)
        logs = self.rpc.get_logs(self.filter)

        # check allowance
        data = contract.functions.allowance(Web3.toChecksumAddress(self.pub[0]), self.sender_checksum).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) == 50000)

        # insufficient balance
        data = contract.functions.transfer(self.sender_checksum, 200000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[0], self.pri[0], contractAddr, data, storage_limit=128)
        assert(result["outcomeStatus"] != "0x0")

        # insuffcient allowance 
        data = contract.functions.transferFrom(Web3.toChecksumAddress(self.pub[0]), self.sender_checksum, 10000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[1], self.pri[1], contractAddr, data, storage_limit=128)
        assert(result["outcomeStatus"] != "0x0")

        # transfer 50000 use allowance
        data = contract.functions.transferFrom(Web3.toChecksumAddress(self.pub[0]), Web3.toChecksumAddress(self.pub[1]), 50000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, storage_limit=64)
        assert(result["outcomeStatus"] == "0x0")

        # get digest and sign it
        ts = int(time.time()) + 7200
        data = contract.functions.getHash(Web3.toChecksumAddress(self.pub[0]), Web3.toChecksumAddress(self.pub[1]), 0, ts, True).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        v, r, s = ecsign(bytes.fromhex(result[2:]), self.pri[0])
        v -= 27
        r = self.fixto64(hex(r))
        s = self.fixto64(hex(s))
        assert(len(r) == 66)
        assert(len(s) == 66)

        # premit
        data = contract.functions.permit(Web3.toChecksumAddress(self.pub[0]), Web3.toChecksumAddress(self.pub[1]), 0, ts, True, v, r, s).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[5], self.pri[5], contractAddr, data, storage_limit=128)
        assert(result["outcomeStatus"] == "0x0")

        # check allowance
        data = contract.functions.allowance(Web3.toChecksumAddress(self.pub[0]), self.sender_checksum).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) == 0)
        data = contract.functions.allowance(Web3.toChecksumAddress(self.pub[0]), Web3.toChecksumAddress(self.pub[1])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(result == '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')

        # burn pub[0]
        data = contract.functions.burn(Web3.toChecksumAddress(self.pub[0]), 50000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[1], self.pri[1], contractAddr, data, storage_limit=64)
        assert(result["outcomeStatus"] == "0x0")

        # check balance
        data = contract.functions.balanceOf(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) == 0)
        data = contract.functions.balanceOf(Web3.toChecksumAddress(self.pub[1])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) == 50000)
        data = contract.functions.totalSupply().buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) == 50000)

    def testDaiJoinContract(self):
        CONTRACT_PATH = "contracts/Dai_bytecode.dat"
        file_dir = os.path.dirname(os.path.realpath(__file__))
        dai = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/Dai_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        data = dai.constructor(1).buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=8239)
        dai_addr = Web3.toChecksumAddress(contractAddr)

        CONTRACT_PATH = "contracts/Vat_bytecode.dat"
        file_dir = os.path.dirname(os.path.realpath(__file__))
        vat = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/Vat_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        data = vat.constructor().buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=10395)
        vat_addr = Web3.toChecksumAddress(contractAddr)

        CONTRACT_PATH = "contracts/DaiJoin_bytecode.dat"
        file_dir = os.path.dirname(os.path.realpath(__file__))
        dai_join = get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/DaiJoin_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        data = dai_join.constructor(vat_addr, dai_addr).buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data, storage_limit=2079)
        dai_join_addr = Web3.toChecksumAddress(contractAddr)

        # mint dai tokens & give approval
        self.tx_conf["to"] = dai_addr
        data = dai.functions.mint(Web3.toChecksumAddress(self.pub[0]), 100000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, dai_addr, data, 0, storage_limit=128)
        assert(result["outcomeStatus"] == "0x0")
        data = dai.functions.approve(dai_join_addr, 100000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[0], self.pri[0], dai_addr, data, 0, storage_limit=64)
        assert(result["outcomeStatus"] == "0x0")
        data = dai.functions.allowance(Web3.toChecksumAddress(self.pub[0]), dai_join_addr).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(dai_addr, data)
        assert_equal(int(result, 0), 100000)
        data = dai.functions.rely(dai_join_addr).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, dai_addr, data, 0, storage_limit=64)
        assert(result["outcomeStatus"] == "0x0")


        # mint dai tokens for join_addr in vat & add approval
        self.tx_conf["to"] = vat_addr
        data = vat.functions.mint(dai_join_addr, 100000000000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.sender, self.priv_key, vat_addr, data, 0, storage_limit=128)
        assert(result["outcomeStatus"] == "0x0")
        data = vat.functions.hope(dai_join_addr).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[0], self.pri[0], vat_addr, data, 0, storage_limit=64)
        assert(result["outcomeStatus"] == "0x0")
        data = vat.functions.balanceOf(dai_join_addr).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(vat_addr, data)
        assert_equal(int(result, 0), 100000000000)

        # join
        self.tx_conf["to"] = dai_join_addr
        data = dai_join.functions.join(Web3.toChecksumAddress(self.pub[0]), 50000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[0], self.pri[0], dai_join_addr, data, 0, storage_limit=320)
        assert(result["outcomeStatus"] == "0x0")

        # check
        self.tx_conf["to"] = dai_addr
        data = dai.functions.balanceOf(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(dai_addr, data)
        assert_equal(int(result, 0), 50000)

        self.tx_conf["to"] = vat_addr
        data = vat.functions.can(dai_join_addr, Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(vat_addr, data)
        assert_equal(int(result, 0), 1)

        data = vat.functions.dai(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(vat_addr, data)
        assert_equal(int(result, 0), 50000000000000000000000000000000)

        # exit
        self.tx_conf["to"] = dai_join_addr
        data = dai_join.functions.exit(Web3.toChecksumAddress(self.pub[0]), 50000).buildTransaction(self.tx_conf)["data"]
        result = self.call_contract(self.pub[0], self.pri[0], dai_join_addr, data, 0, storage_limit=128)
        assert(result["outcomeStatus"] == "0x0")

        # check
        self.tx_conf["to"] = dai_addr
        data = dai.functions.balanceOf(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(dai_addr, data)
        assert_equal(int(result, 0), 100000)

        self.tx_conf["to"] = vat_addr
        data = vat.functions.can(dai_join_addr, Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(vat_addr, data)
        assert_equal(int(result, 0), 0)

        data = vat.functions.dai(Web3.toChecksumAddress(self.pub[0])).buildTransaction(self.tx_conf)["data"]
        result = self.rpc.call(vat_addr, data)
        assert_equal(int(result, 0), 0)

    def run_test(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        file_path = os.path.join(file_dir, "..", "internal_contract", "metadata", "Staking.json")
        staking_contract_dict = json.loads(open(os.path.join(file_path), "r").read())
        staking_contract = get_contract_instance(contract_dict=staking_contract_dict)
        staking_contract_addr = Web3.toChecksumAddress("0888000000000000000000000000000000000002")

        self.problem = "0x2bc79b7514884ab00da924607d71542cc4fed3beb8518e747726ae30ab6c7944"
        self.solution = "0xc4d2751c52311d0d7efe44e5c4195e058ad5ef4bb89b3e1761b24dc277b132c2"
        self.priv_key = default_config["GENESIS_PRI_KEY"]
        self.sender = encode_hex_0x(priv_to_addr(self.priv_key))
        self.sender_checksum = Web3.toChecksumAddress(self.sender)
        self.pub = []
        self.pri = []
        self.rpc = RpcClient(self.nodes[0])
        gas = CONTRACT_DEFAULT_GAS
        gas_price = 10

        # lock token for genesis account
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.tx_conf['to'] = staking_contract_addr
        tx_data = decode_hex(staking_contract.functions.deposit(1000000 * 10 ** 18).buildTransaction(self.tx_conf)["data"])
        tx = self.rpc.new_tx(value=0, receiver=staking_contract_addr, data=tx_data, gas=gas, gas_price=gas_price)
        self.rpc.send_tx(tx, True)

        for i in range(10):
            priv_key = random.randint(0, 2 ** 256).to_bytes(32, "big")
            pub_key = encode_hex_0x(priv_to_addr(priv_key))
            self.pub.append(pub_key)
            self.pri.append(priv_key)
            transaction = self.rpc.new_tx(sender=self.sender, receiver=pub_key, value=1000000 * 10 ** 18, priv_key=self.priv_key)
            self.rpc.send_tx(transaction, True)
            # deposit 10000 tokens
            tx_data = decode_hex(staking_contract.functions.deposit(10000 * 10 ** 18).buildTransaction(self.tx_conf)["data"])
            tx = self.rpc.new_tx(value=0, sender=pub_key, receiver=self.tx_conf["to"], gas=gas, data=tx_data, priv_key=priv_key)
            self.rpc.send_tx(tx)
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.filter = Filter(from_epoch="earliest", to_epoch="latest_state")
        self.testEventContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.testBallotContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.testPayContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.testHTLCContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.testDaiContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.testMappingContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price), "chainId":0}
        self.testDaiJoinContract()
        self.log.info("Pass")

    def address_to_topic(self, address):
        return "0x" + address[2:].zfill(64)

    def number_to_topic(self, number):
        return "0x" + ("%x" % number).zfill(64)

    def deploy_contract(self, sender, priv_key, data_hex, storage_limit):
        c0 = self.rpc.get_collateral_for_storage(self.rpc.GENESIS_ADDR)
        tx = self.rpc.new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key, storage_limit=storage_limit)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        self.log.info("deploy_contract storage_limit={}".format((self.rpc.get_collateral_for_storage(self.rpc.GENESIS_ADDR) - c0) // self.collateral_per_byte))
        assert_equal(self.rpc.get_collateral_for_storage(self.rpc.GENESIS_ADDR), c0 + storage_limit * self.collateral_per_byte)
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex, value=0, storage_limit=0, gas=CONTRACT_DEFAULT_GAS):
        c0 = self.rpc.get_collateral_for_storage(sender)
        tx = self.rpc.new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, value=value, storage_limit=storage_limit, gas=gas)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        self.log.info("call_contract storage_limit={}".format((self.rpc.get_collateral_for_storage(sender) - c0) // self.collateral_per_byte))
        return receipt

    def fixto64(self, x):
      return '0x' + ('0' * (66 - len(x))) + x[2:]

if __name__ == "__main__":
    ContractBenchTest().main()
