from os.path import dirname, join
from pathlib import Path
import json
from dataclasses import dataclass
from typing import Literal, Dict, Type, Optional, cast, Union, List

from conflux_web3 import Web3 as CWeb3
from conflux_web3.contract import ConfluxContract
from conflux_web3.client import ConfluxClient
from typing import Any
from web3.types import RPCEndpoint
from conflux_web3._utils.rpc_abi import (
    RPC
)

from conflux_web3.middleware.base import ConfluxWeb3Middleware

from web3 import Web3
from web3.eth import Eth
from web3.middleware.signing import SignAndSendRawMiddlewareBuilder
from test_framework.test_framework import ConfluxTestFramework, RpcClient, start_p2p_connection
from test_framework.util import *
from test_framework.block_gen_thread import BlockGenThread


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


def load_contract_metadata(name: str):
    path = Path(join(dirname(__file__), "..", "test_contracts", "artifacts"))
    try:
        found_file = next(path.rglob(f"{name}.json"))
        return json.loads(open(found_file, "r").read())
    except StopIteration:
        raise Exception(f"Cannot found contract {name}'s metadata")


def cfx_contract(name: str, framework: Optional[ConfluxTestFramework] = None):
    metadata = load_contract_metadata(name)
    if framework is None:
        raise ValueError("Framework cannot be None")
    w3: CWeb3 = getattr(framework, "w3")
    contract = w3.cfx.contract(
        abi=metadata["abi"], bytecode=metadata["bytecode"])
    return contract

@dataclass
class Account:
    address: str
    key: str

class ConfluxTestFrameworkForContract(ConfluxTestFramework):
    
    client: RpcClient
    w3: CWeb3
    ew3: Web3
    cfx: ConfluxClient
    eth: Eth
    
    def __init__(self):
        super().__init__()

    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["executive_trace"] = "true"  
        
    def setup_w3(self):
        client = self.client
        log = self.log
        self.w3 = CWeb3(CWeb3.HTTPProvider(f'http://{self.nodes[0].ip}:{self.nodes[0].rpcport}/'))
        self.ew3 = Web3(Web3.HTTPProvider(f'http://{self.nodes[0].ip}:{self.nodes[0].ethrpcport}/'))

        self.cfx = self.w3.cfx
        self.eth = self.ew3.eth
        
        self.w3.wallet.add_accounts(self.core_accounts)
        self.w3.cfx.default_account = self.core_accounts[0].address
        
        self.ew3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(self.evm_secrets)) # type: ignore
        self.eth.default_account = self.evm_accounts[0].address
        
        class TestNodeMiddleware(ConfluxWeb3Middleware):
            def request_processor(self, method: RPCEndpoint, params: Any) -> Any:
                if method == RPC.cfx_sendRawTransaction or method == RPC.cfx_sendTransaction:
                    client.node.wait_for_phase(["NormalSyncPhase"])
                return super().request_processor(method, params)

            def response_processor(self, method: RPCEndpoint, response: Any):
                if method == RPC.cfx_getTransactionReceipt:
                    if "result" in response and response["result"] is None:
                        log.debug("Auto generate 5 blocks because did not get tx receipt")
                        client.generate_blocks_to_state(num_txs=1)  # why num_txs=1?
                return response
        self.w3.middleware_onion.add(TestNodeMiddleware)
        
    def start_block_gen(self):
        BlockGenThread(self.nodes, self.log).start()

    def before_test(self):
        if "executive_trace" not in self.conf_parameters or not bool(self.conf_parameters["executive_trace"]):
            raise AssertionError(
                "Trace should be enabled for contract toolkit")
        super().before_test()
        self.rpc = self.nodes[0].rpc
        self.client = RpcClient(self.nodes[0])
        start_p2p_connection(self.nodes)
        # enable cfx_maxPriorityFeePerGas
        # or Error(Epoch number larger than the current pivot chain tip) would be raised
        self.client.generate_blocks_to_state(num_txs=1) 

        self.setup_w3()

    def cfx_contract(self, name) -> Type[ConfluxContract]:
        return cfx_contract(name, self)

    def assert_tx_exec_error(self, tx_hash, err_msg):
        self.client.wait_for_receipt(tx_hash)
        receipt = self.client.get_transaction_receipt(tx_hash)
        assert_equal(
            receipt["txExecErrorMsg"],
            err_msg
        )
    
    def deploy_contract(self, name, transact_args = {}) -> ConfluxContract:
        tx_hash = self.cfx_contract(name).constructor().transact(transact_args)
        receipt = tx_hash.executed(timeout=30)
        return self.cfx_contract(name)(cast(str, receipt["contractCreated"]))
    
    def deploy_contract_2(self, name, seed, *args, **kwargs) -> ConfluxContract:
        if self.create2factory is None:
            raise Exception("Create2Factory is not deployed")
        contract_factory = self.cfx_contract(name)
        deploy_code = contract_factory.constructor(*args, **kwargs)._build_transaction()["data"]
        dest_address = self.create2factory.functions.callCreate2(seed, deploy_code).call()
        tx_hash = self.create2factory.functions.callCreate2(seed, deploy_code).transact()
        self.client.generate_blocks(10)
        tx_hash.executed(timeout=30)
        return contract_factory(dest_address)

    def internal_contract(self, name: InternalContractName):
        return self.w3.cfx.contract(name=name, with_deployment_info=True)

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
            return receipt
        else:
            return tx.hash_hex()
    
    def initialize_accounts(self, number = 10, value = 100) -> List[Account]:
        def initialize_new_account() -> Account:
            (address, priv) = self.client.rand_account()
            if value > 0:
                self.cfx_transfer(address, value = value)
            return Account(address, priv)
        
        return [initialize_new_account() for _ in range(number)]

    @property
    def adminControl(self):
        return self.w3.cfx.contract(name="AdminControl", with_deployment_info=True)

    @property
    def sponsorControl(self):
        return self.w3.cfx.contract(name="SponsorWhitelistControl", with_deployment_info=True)

    def deploy_create2(self):
        self.create2factory = self.deploy_contract("Create2Factory")
    
if __name__ == "__main__":
    ConfluxTestFrameworkForContract().main()