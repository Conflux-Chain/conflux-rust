#!/usr/bin/env python3
# import os, sys
# sys.path.insert(1, os.path.join(sys.path[0], '..'))

from base import Web3Base
from conflux.config import default_config
from test_framework.util import *
from web3 import Web3

toHex = Web3.toHex

class DebugTraceTxTest(Web3Base):
    def set_test_params(self):
        super().set_test_params()
        self.conf_parameters["public_evm_rpc_apis"] = "\"eth,ethdebug\""

    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')
        # initialize EVM account
        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')
        self.cross_space_transfer(self.evmAccount.address, 100 * 10 ** 18)
        assert_equal(self.nodes[0].eth_getBalance(self.evmAccount.address), hex(100 * 10 ** 18))

        # self.common_cfx_transfer_tx_trace()
        erc20_addr = self.contract_deploy_tx_trace()
        erc20_transfer_hash = self.erc20_transfer_tx_trace(erc20_addr)
        self.noop_tracer(erc20_transfer_hash)
        self.four_byte_tracer(erc20_transfer_hash)
        self.call_tracer(erc20_transfer_hash)
        self.check_opcode_trace_with_config(erc20_transfer_hash)

    def trace_tx(self, tx_hash, opts = None):
        trace = self.nodes[0].ethrpc.debug_traceTransaction(toHex(tx_hash), opts)
        return trace

    def common_cfx_transfer_tx_trace(self):
        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        
        signed = self.evmAccount.signTransaction({
            "to": self.evmAccount.address,
            "value": 1,
            "gasPrice": 1,
            "gas": 210000,
            "nonce": nonce,
            "chainId": self.w3.eth.chainId,
        })

        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])
        self.rpc.generate_blocks(20, 1)
        trace = self.nodes[0].ethrpc.debug_traceTransaction(toHex(return_tx_hash))

        assert_equal(trace["failed"], False)
        assert_equal(trace["gas"], 21000)
        assert_equal(trace["returnValue"], "")
        assert_equal(trace["structLogs"], [])

    def contract_deploy_tx_trace(self):
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../contracts/erc20_bytecode.dat")
        assert(os.path.isfile(bytecode_file))
        bytecode = open(bytecode_file).read()

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        signed = self.evmAccount.signTransaction({
            "to": None,
            "value": 0,
            "gasPrice": 1,
            "gas": 10000000,
            "nonce": nonce,
            "chainId": self.w3.eth.chainId,
            "data": bytecode,
        })

        return_tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])

        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)

        receipt = self.w3.eth.get_transaction_receipt(return_tx_hash)
        assert_equal(receipt["status"], 1)

        trace = self.nodes[0].ethrpc.debug_traceTransaction(toHex(return_tx_hash))
        assert_equal(trace["failed"], False)
        oplog_len = len(trace["structLogs"])
        assert_equal(oplog_len > 0, True)
        # print(trace["structLogs"][oplog_len-1])
        assert_equal(trace["structLogs"][oplog_len-1]["op"], "RETURN")

        return receipt["contractAddress"]

    def erc20_transfer_tx_trace(self, erc20_address):
        abi = self.load_abi_from_contracts_folder("erc20")
        erc20 = self.w3.eth.contract(address=erc20_address, abi=abi)

        # balance = erc20.functions.balanceOf(self.evmAccount.address).call()
        target_addr = Web3.toChecksumAddress("0x8b14d287b4150ff22ac73df8be720e933f659abc")

        data = erc20.encodeABI(fn_name="transfer", args=[target_addr, 100])

        nonce = self.w3.eth.getTransactionCount(self.evmAccount.address)
        signed = self.evmAccount.signTransaction({
            "to": erc20_address,
            "value": 0,
            "gasPrice": 1,
            "gas": 1000000,
            "nonce": nonce,
            "chainId": self.w3.eth.chainId,
            "data": data,
        })

        tx_hash = self.w3.eth.sendRawTransaction(signed["rawTransaction"])

        # why this method is not working?
        # tx_hash = erc20.functions.transfer(target_addr, 100).transact()
        
        self.rpc.generate_block(1)
        self.rpc.generate_blocks(20, 1)
        # receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        trace = self.trace_tx(tx_hash)

        assert_equal(trace["failed"], False)
        oplog_len = len(trace["structLogs"])
        assert_equal(oplog_len > 0, True)
        assert_equal(trace["structLogs"][oplog_len-1]["op"], "RETURN")

        return tx_hash
    
    def noop_tracer(self, tx_hash):
        noop_trace = self.trace_tx(tx_hash, {"tracer": "noopTracer"})
        assert_equal(noop_trace, {})

    def four_byte_tracer(self, tx_hash):
        four_byte_trace = self.trace_tx(tx_hash, {"tracer": "4byteTracer"})
        assert_equal(four_byte_trace, {'0xa9059cbb-64': 1})

    def call_tracer(self, tx_hash):
        call_trace = self.trace_tx(tx_hash, {"tracer": "callTracer"})
        assert_equal(call_trace["from"], "0xfcad0b19bb29d4674531d6f115237e16afce377c")
        assert_equal(call_trace["to"], "0x8bfc6fd9437cf1879fb84aade867b6e81efb5631")
        assert_equal(call_trace["type"], 'CALL')
        assert_equal(call_trace["value"], "0x0")
        assert_equal(call_trace["output"], "0x0000000000000000000000000000000000000000000000000000000000000001")

    def check_opcode_trace_with_config(self, tx_hash):
        trace = self.trace_tx(tx_hash, {
            "enableMemory": True,
            "disableStack": False,
            "disableStorage": False,
            "enableReturnData": True
        })

        oplog_len = len(trace["structLogs"])
        assert_equal(trace["failed"], False)
        assert_equal(oplog_len, 231)
        # print(len(trace["structLogs"]))

        # limit parameter test
        limited_trace = self.trace_tx(tx_hash, {
            "enableMemory": True,
            "disableStack": False,
            "disableStorage": False,
            "enableReturnData": True,
            "limit": 10
        })
        assert_equal(len(limited_trace["structLogs"]), 10)

        no_stack_storage_trace = self.trace_tx(tx_hash, {
            "enableMemory": True,
            "disableStack": True,
            "disableStorage": True,
            "enableReturnData": True
        })

        disable_all_trace = self.trace_tx(tx_hash, {
            "enableMemory": False,
            "disableStack": True,
            "disableStorage": True,
            "enableReturnData": False
        })

        for i, oplog in enumerate(trace["structLogs"]):
            oplog = trace["structLogs"][i]
            
            if "memory" in oplog:
                assert_equal("memory" in disable_all_trace["structLogs"][i], False)

            if "returnData" in oplog:
                assert_equal("returnData" in disable_all_trace["structLogs"][i], False)
            
            if "stack" in oplog:
                assert_equal("stack" in no_stack_storage_trace["structLogs"][i], False)
            
            if "storage" in oplog:
                assert_equal("storage" in no_stack_storage_trace["structLogs"][i], False)


if __name__ == "__main__":
    DebugTraceTxTest().main()