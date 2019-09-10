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
from conflux.utils import sha3 as keccak
from conflux.utils import encode_hex, privtoaddr, parse_as_int

from web3 import Web3
from easysolc import Solc

class HTLCTest(SmartContractBenchBase):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

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
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, bytecode)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 1)

        # construct contract object 
        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/event_abi_new.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        self.tx_conf["to"] = contractAddr
        
        # interact with foo()
        data = contract.functions.foo().buildTransaction(self.tx_conf)["data"];
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 2)
        assert_equal(logs[-1]["topics"][1], self.address_to_topic(self.sender))
        assert_equal(logs[-1]["topics"][2], self.number_to_topic(1))


        # interact with goo(10), will pass modifier, emit new event
        data = contract.functions.goo(10).buildTransaction(self.tx_conf)["data"];
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 3)
        assert_equal(logs[-1]["topics"][1], self.address_to_topic(self.sender))
        assert_equal(logs[-1]["topics"][2], self.number_to_topic(11))
        
        # interact with goo(10), will not pass modifier, no event emitted
        data = contract.functions.goo(10).buildTransaction(self.tx_conf)["data"];
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 3)
        
        # call const function hoo()
        data = contract.functions.hoo().buildTransaction(self.tx_conf)["data"];
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.number_to_topic(11))

        # call const function byte32oo(solution)
        data = contract.functions.byte32oo(self.solution).buildTransaction(self.tx_conf)["data"];
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.solution)
        
        # call const function getSha256(solution)
        data = contract.functions.getSha256(self.solution).buildTransaction(self.tx_conf)["data"];
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.problem)
    
    def testBallotContract(self):
        CONTRACT_PATH = "contracts/ballot_bytecode.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/ballot_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        
        # deploy contract
        data = contract.constructor(10).buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr

        # interact with vote()
        data = contract.functions.vote(5).buildTransaction(self.tx_conf)["data"];
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 1)
        assert_equal(logs[-1]["data"], self.number_to_topic(5))
        
        # call const function winningProposal()
        data = contract.functions.winningProposal().buildTransaction(self.tx_conf)["data"];
        result = self.rpc.call(contractAddr, data)
        assert_equal(result, self.number_to_topic(5))
    
    def testHTLCContract(self):
        CONTRACT_PATH = "contracts/htlc_bytecode_new.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/htlc_abi_new.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        
        # deploy contract
        data = contract.constructor().buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 1)
        assert_equal(logs[-1]["topics"][1], self.address_to_topic(self.sender))
        assert_equal(logs[-1]["topics"][2], self.number_to_topic(16))

        # call getNow()
        data = contract.functions.getNow().buildTransaction(self.tx_conf)["data"];
        result = self.rpc.call(contractAddr, data)
        assert(int(result, 0) - int(time.time()) < 5)

        b0 = self.rpc.get_balance(self.sender)
        fee = 10000000
        # interact with newContract(), sender send conflux to himself
        time_lock = int(time.time()) + 7200
        data = contract.functions.newContract(self.sender_checksum, self.problem, time_lock).buildTransaction(self.tx_conf)["data"];
        cost = 5000000000000000000
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, cost)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(len(logs), l + 2)
        assert_equal(self.rpc.get_balance(contractAddr), cost)
        assert_equal(self.rpc.get_balance(self.sender), b0 - cost - fee)
        contract_id = logs[-1]["topics"][1]

        # call getContract
        data = contract.functions.getContract(contract_id).buildTransaction(self.tx_conf)["data"];
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
        data = contract.functions.withdraw(contract_id, self.solution).buildTransaction(self.tx_conf)["data"];
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data)
        assert_equal(self.rpc.get_balance(contractAddr), 0)
        assert_equal(self.rpc.get_balance(self.sender), b0 - fee * 2)
        
        # call getContract
        data = contract.functions.getContract(contract_id).buildTransaction(self.tx_conf)["data"];
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
    
    def testPayContract(self):
        CONTRACT_PATH = "contracts/pay_bytecode.dat"
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)

        # construct contract object 
        solc = Solc()
        file_dir = os.path.dirname(os.path.realpath(__file__))
        contract = solc.get_contract_instance(
            abi_file = os.path.join(file_dir, "contracts/pay_abi.json"),
            bytecode_file = os.path.join(file_dir, CONTRACT_PATH),
        )
        
        # deploy contract
        data = contract.constructor().buildTransaction(self.tx_conf)["data"]
        receipt, contractAddr = self.deploy_contract(self.sender, self.priv_key, data)
        contractAddr = Web3.toChecksumAddress(contractAddr)
        self.tx_conf["to"] = contractAddr
        logs = self.rpc.get_logs(self.filter)
        l = len(logs)
        
        b0 = self.rpc.get_balance(self.sender)
        # interact with recharge()
        data = contract.functions.recharge().buildTransaction(self.tx_conf)["data"];
        cost = 5000000000000000000
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, cost)
        b1 = self.rpc.get_balance(self.sender)
        bc = self.rpc.get_balance(contractAddr)
        assert_equal(bc, cost)
        
        #interact with withdraw
        data = contract.functions.withdraw(self.sender_checksum).buildTransaction(self.tx_conf)["data"];
        result = self.call_contract(self.sender, self.priv_key, contractAddr, data, 0)
        b2 = self.rpc.get_balance(self.sender)
        bc = self.rpc.get_balance(contractAddr)
        logs = self.rpc.get_logs(self.filter)
        assert_equal(bc, 0)
        

    def run_test(self):
        self.problem = "0x2bc79b7514884ab00da924607d71542cc4fed3beb8518e747726ae30ab6c7944";
        self.solution = "0xc4d2751c52311d0d7efe44e5c4195e058ad5ef4bb89b3e1761b24dc277b132c2";
        self.priv_key = default_config["GENESIS_PRI_KEY"]
        self.sender = encode_hex_0x(privtoaddr(self.priv_key))
        self.sender_checksum = Web3.toChecksumAddress(self.sender)
        self.rpc = RpcClient(self.nodes[0])
        nonce = 0
        gas = 50000000
        gas_price = 10
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price)}

        self.filter = Filter(from_epoch="earliest", to_epoch="latest_mined")
        result = self.rpc.get_logs(self.filter)
        assert_equal(result, [])

        self.testEventContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price)}
        self.testBallotContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price)}
        self.testPayContract()
        self.tx_conf = {"from":self.sender, "gas":int_to_hex(gas), "gasPrice":int_to_hex(gas_price)}
        self.testHTLCContract()
        self.log.info("Pass")

    def address_to_topic(self, address):
        return "0x" + address[2:].zfill(64)

    def number_to_topic(self, number):
        return "0x" + ("%x" % number).zfill(64)

    def deploy_contract(self, sender, priv_key, data_hex):
        tx = self.rpc.new_contract_tx(receiver="", data_hex=data_hex, sender=sender, priv_key=priv_key)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_receipt(tx.hash_hex())
        address = receipt["contractCreated"]
        assert_is_hex_string(address)
        return receipt, address

    def call_contract(self, sender, priv_key, contract, data_hex, value=0):
        tx = self.rpc.new_contract_tx(receiver=contract, data_hex=data_hex, sender=sender, priv_key=priv_key, value=value)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_receipt(tx.hash_hex())
        return receipt

if __name__ == "__main__":
    HTLCTest().main()
