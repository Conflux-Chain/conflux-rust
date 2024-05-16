from os.path import dirname, join
from pathlib import Path
import json
from dataclasses import dataclass

from typing import Literal, Dict
import types

from web3 import Web3
from web3.contract import ContractFunction, Contract, ContractConstructor, get_abi_output_types
from conflux.address import b32_address_to_hex
from conflux.config import default_config
from conflux.utils import priv_to_addr
from test_framework.blocktools import encode_hex_0x
from test_framework.test_framework import ConfluxTestFramework, RpcClient, start_p2p_connection
from test_framework.util import *
from eth_utils import decode_hex


BASE = int(1e18)
ZERO_ADDRESS = f"0x{'0'*40}"

InternalContractName = Literal["AdminControl", "SponsorWhitelistControl",
                               "Staking", "ConfluxContext", "PoSRegister", "CrossSpaceCall", "ParamsControl"]

INTERNAL_CONTRACT_MAP: Dict[InternalContractName, str] = {
    "AdminControl": "0x0888000000000000000000000000000000000000",
    "SponsorWhitelistControl": "0x0888000000000000000000000000000000000001",
    "Staking": "0x0888000000000000000000000000000000000002",
    "ConfluxContext": "0x0888000000000000000000000000000000000004",
    "PoSRegister": "0x0888000000000000000000000000000000000005",
    "CrossSpaceCall": "0x0888000000000000000000000000000000000006",
    "ParamsControl": "0x0888000000000000000000000000000000000007",
}


def _load_contract_metadata(name: str):
    path = Path(join(dirname(__file__), "..", "test_contracts", "artifacts"))
    try:
        found_file = next(path.rglob(f"{name}.json"))
        return json.loads(open(found_file, "r").read())
    except StopIteration:
        raise Exception(f"Cannot found contract {name}'s metadata")


def cfx_contract(name: str, framework: ConfluxTestFramework = None) -> Contract:
    metadata = _load_contract_metadata(name)
    w3 = Web3()
    contract = w3.eth.contract(
        abi=metadata["abi"], bytecode=metadata["bytecode"])

    contract.framework = framework
    _enact_contract(contract)
    return contract


def cfx_internal_contract(name: InternalContractName, framework: ConfluxTestFramework = None) -> Contract:
    contract_addr = INTERNAL_CONTRACT_MAP[name]
    return cfx_contract(name, framework).at(contract_addr)


def _add_address(self: Contract, address: str) -> Contract:
    w3 = Web3()
    new_contract = w3.eth.contract(
        abi=self.abi, bytecode=self.bytecode, address=Web3.toChecksumAddress(address))

    new_contract.framework = self.framework
    _enact_contract(new_contract)
    return new_contract


def _deploy_contract(self: Contract, transact_args = None, *args, **kwargs) -> Contract:
    if not hasattr(self, "framework"):
        raise Exception("Contract does not hold Conflux framework")
    
    if transact_args is None:
        transact_args = {}

    receipt = _cfx_transact(self.constructor(
        *args, **kwargs), framework=self.framework, **transact_args)
    return _add_address(self, receipt["contractCreated"])


def _deploy_create2_contract(self: Contract, seed, *args, **kwargs) -> Contract:
    if not hasattr(self, "framework"):
        raise Exception("Contract does not hold Conflux framework")

    if not hasattr(self.framework, "create2factory"):
        raise Exception("Create2Factory is not deployed")

    deployCode = _cfx_data(self.constructor(*args, **kwargs))
    receipt = self.framework.create2factory.functions.callCreate2(
        seed, deployCode).cfx_transact()

    trace = self.framework.rpc.trace_transaction(receipt["transactionHash"])
    deploy_item = [t for t in trace if t["type"] == "create_result"][0]
    created_address = b32_address_to_hex(deploy_item["action"]["addr"])

    return _add_address(self, created_address)


def _enact_contract(contract: Contract):
    framework = contract.framework

    contract.at = types.MethodType(_add_address, contract)
    contract.deploy = types.MethodType(_deploy_contract, contract)
    contract.deploy2 = types.MethodType(_deploy_create2_contract, contract)

    for _, obj in contract.functions.__dict__.items():
        if isinstance(obj, ContractFunction):
            obj.framework = framework


def _get_framework(fn: ContractFunction) -> ConfluxTestFramework:
    if hasattr(fn, "framework") and isinstance(fn.framework, ConfluxTestFramework):
        pass
    else:
        raise Exception(
            f"Not bind test framework when making call for {fn.function_identifier}")

    return fn.framework


def _cfx_transact(self: ContractFunction, value=None, decimals: int = 18, gas=None, storage_limit=None, priv_key=None, err_msg = None, framework=None):
    if framework is None:
        framework = _get_framework(self)

    tx = self.build_transaction(
        {"gas": 3000000, "gasPrice": 1, "chainId": 1})
    data = bytes.fromhex(tx["data"][2:])

    if value is not None:
        value = int(value * (10**decimals))
    else:
        value = 0

    if storage_limit is None:
        if len(tx["to"]) == 0:
            storage_limit = 30000
        else:
            storage_limit = 1024

    if gas is None:
        if len(tx["to"]) == 0:
            gas = 10_000_000
        else:
            gas = 3_000_000

    if len(tx["to"]) == 0:
        receiver = None
    else:
        receiver = tx["to"]

    if gas is None:
        if len(data) > 0:
            gas = 3000000
        else:
            gas = 21000

    tx = framework.client.new_contract_tx(
        receiver=receiver, value=value, data_hex=tx["data"], priv_key=priv_key, gas=gas, storage_limit=storage_limit)
    framework.client.send_tx(tx, True)
    framework.wait_for_tx([tx], err_msg is None)
    receipt = framework.client.get_transaction_receipt(tx.hash_hex())
    if err_msg is not None:
        assert_equal(receipt["txExecErrorMsg"], err_msg)
    # self.log.info(receipt)
    return receipt
    


def _cfx_call(self: ContractFunction, framework=None, sender=None, raw_output=False):
    if framework is None:
        framework = _get_framework(self)

    tx = self.build_transaction(
        {"gas": 3000000, "gasPrice": 1, "chainId": 1})
    result = framework.client.call(tx["to"], tx["data"], sender=sender)

    if not raw_output:
        output_types = get_abi_output_types(self.abi)
        ans = self.web3.codec.decode_abi(output_types, decode_hex(result))
        if len(ans) == 0:
            return
        elif len(ans) == 1:
            return ans[0]
        else:
            return ans
    else:
        return result


def _cfx_data(self: ContractFunction):
    tx = self.build_transaction(
        {"gas": 3000000, "gasPrice": 1, "chainId": 1})
    return tx["data"]


setattr(ContractFunction, 'cfx_transact', _cfx_transact)
setattr(ContractFunction, 'cfx_call', _cfx_call)
setattr(ContractFunction, 'data', _cfx_data)

setattr(ContractConstructor, 'cfx_transact', _cfx_transact)
setattr(ContractConstructor, 'cfx_call', _cfx_call)
setattr(ContractConstructor, 'data', _cfx_data)


@dataclass
class Account:
    address: str
    key: str

class ConfluxTestFrameworkForContract(ConfluxTestFramework):
    def __init__(self):
        super().__init__()

    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["executive_trace"] = "true"  

    def before_test(self):
        if "executive_trace" not in self.conf_parameters or not bool(self.conf_parameters["executive_trace"]):
            raise AssertionError(
                "Trace should be enabled for contract toolkit")
        super().before_test()
        self.rpc = self.nodes[0].rpc
        self.client = RpcClient(self.nodes[0])
        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        self.w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))
        start_p2p_connection(self.nodes)
        self.deploy_create2()

        self.genesis_key = default_config["GENESIS_PRI_KEY"]
        self.genesis_addr = Web3.toChecksumAddress(encode_hex_0x(priv_to_addr(self.genesis_key)))
        self.genesis_key2 = default_config["GENESIS_PRI_KEY_2"]
        self.genesis_addr2 = Web3.toChecksumAddress(encode_hex_0x(priv_to_addr(self.genesis_key2)))

    def cfx_contract(self, name):
        return cfx_contract(name, self)

    def internal_contract(self, name: InternalContractName):
        return cfx_internal_contract(name, self)

    def cfx_transfer(self, receiver, value=None, gas_price=1, priv_key=None, decimals: int = 18, nonce = None, execute: bool = True):
        if value is not None:
            value = int(value * (10**decimals))
        else:
            value = 0

        tx = self.client.new_tx(
            receiver=receiver, gas_price=gas_price, priv_key=priv_key, value=value, nonce=nonce)
        self.client.send_tx(tx, execute)
        if execute:
            self.wait_for_tx([tx], True)
            receipt = self.client.get_transaction_receipt(tx.hash_hex())
            # self.log.info(receipt)
            return receipt
        else:
            return tx.hash_hex()
    
    def initialize_accounts(self, number = 10, value = 100) -> List[Account]:
        def initialize_new_account() -> (str, bytes):
            (address, priv) = self.client.rand_account()
            if value > 0:
                self.cfx_transfer(address, value = value)
            return Account(address, priv)
        
        return [initialize_new_account() for _ in range(number)]

    @property
    def adminControl(self):
        return self.internal_contract("AdminControl")

    @property
    def sponsorControl(self):
        return self.internal_contract("SponsorWhitelistControl")

    def deploy_create2(self):
        self.create2factory: Contract = self.cfx_contract("Create2Factory").deploy()
