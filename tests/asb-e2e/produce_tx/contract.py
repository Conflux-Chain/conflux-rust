from os.path import dirname, join
from pathlib import Path
import json

from solcx import compile_files
from web3 import Web3
from web3.contract import  Contract as Web3Contract

from .transaction import TxParam
from .calldata_template import CalldataTemplate
from . import log




ALL_OUTPUT_VALUES = ["abi", "asm", "ast", "bin", "bin-runtime", "devdoc", "interface", "opcodes", "userdoc"]
FAKE_TO = "0x" + "0" * 40

class Contract:
    def __init__(self, contract: Web3Contract, address = None):
        self.contract = contract

    def at_address(self, address):
        w3 = Web3()
        return Contract(w3.eth.contract(abi=self.contract.abi, bytecode=self.contract.bytecode, address = Web3.toChecksumAddress(address)))
            

    @staticmethod
    def from_sol(file_path, name):
        path = join(dirname(__file__), "contract", file_path)
        compiled_sol = compile_files([path], output_values=ALL_OUTPUT_VALUES, optimize=True, optimize_runs=200)
        contract = compiled_sol[path + ':' + name]
        w3 = Web3()
        return Contract(w3.eth.contract(abi=contract['abi'], bytecode=contract['bin']))

    @staticmethod
    def from_artifacts(name):
        path = Path(join(dirname(__file__), "..", "..", "test_contracts", "artifacts", "contracts"))
        try:
            found_file = next(path.rglob(f"{name}.json"))
            metadata = json.loads(open(found_file, "r").read())
            w3 = Web3()
            return Contract(w3.eth.contract(abi=metadata["abi"], bytecode=metadata["bytecode"]))
        except StopIteration:
            raise Exception(f"Cannot found contract {name}'s metadata")
        
    @property
    def address(self):
        if self.contract.address is None:
            raise Exception("Address has not been set")
        else:
            return self.contract.address

    @property
    def address_or_fake(self):
        if self.contract.address is None:
            return Web3.toChecksumAddress(FAKE_TO)
        else:
            return self.contract.address


    def deploy(self, sender_index, *args):
        calldata = self.contract.constructor(*args).data_in_transaction
        tx_param = TxParam(sender_index = sender_index, data = calldata)
        tx_param.assign_nonce()
        
        return tx_param, self.at_address(tx_param.contract_address())

    def call(self, sender_index, name, *args):
        func = getattr(self.contract.functions, name)
        calldata = func(*args).buildTransaction({"gas": 21000, "gasPrice":1, "chainId": 1})["data"][2:]

        

        tx_param = TxParam(sender_index=sender_index, action=bytearray.fromhex(self.address[2:]), data = calldata)
        tx_param.assign_nonce()
        return tx_param
    
    def build_template(self, name, *args) -> CalldataTemplate:
        func = getattr(self.contract.functions, name)
        calldata = func(*args).buildTransaction({"gas": 21000, "gasPrice":1, "chainId": 1})["data"][2:]
        return CalldataTemplate(calldata, self.address)