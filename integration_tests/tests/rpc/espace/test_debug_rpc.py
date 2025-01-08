import pytest
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util import load_contract_metadata
from integration_tests.conflux.rpc import RpcClient
from typing import Type

@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1
            self.conf_parameters["public_evm_rpc_async_apis"] = "\"all\""

        def setup_network(self):
            self.setup_nodes()
            self.rpc = RpcClient(self.nodes[0])

    return DefaultFramework

def test_trace_simple_cfx_transfer(ew3, evm_accounts):
    account = evm_accounts[0]
    to_address = ew3.eth.account.create().address
    tx_hash = ew3.eth.send_transaction({
        "to": to_address,
        "value": ew3.to_wei(1, "ether"),
        "from": account.address
    })
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert ew3.eth.get_balance(to_address) == ew3.to_wei(1, "ether")

    tx_trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash])
    assert tx_trace['failed'] == False
    assert tx_trace['gas'] == 21000
    assert tx_trace['returnValue'] == ''
    assert len(tx_trace['structLogs']) == 0

def test_trace_deploy_contract(ew3, evm_accounts):
    account = evm_accounts[0]
    contract_meta = load_contract_metadata("MyToken")
    TokenContract = ew3.eth.contract(abi=contract_meta['abi'], bytecode=contract_meta['bytecode'])
    tx_hash = TokenContract.constructor(account.address).transact()
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    deploy_receipt = ew3.eth.get_transaction_receipt(tx_hash)
    assert deploy_receipt["status"] == 1

    erc20_address = deploy_receipt["contractAddress"]
    
    token_contract = ew3.eth.contract(address=erc20_address, abi=contract_meta['abi'])

    mint_hash = token_contract.functions.mint(account.address, ew3.to_wei(100, "ether")).transact()
    ew3.eth.wait_for_transaction_receipt(mint_hash)

    to_address = ew3.eth.account.create().address
    transfer_hash = token_contract.functions.transfer(to_address, ew3.to_wei(1, "ether")).transact()
    ew3.eth.wait_for_transaction_receipt(transfer_hash)

    check_deploy_trace(ew3, tx_hash)
    check_transfer_trace(ew3, transfer_hash)
    check_noop_trace(ew3, transfer_hash)
    check_four_byte_trace(ew3, transfer_hash)
    check_call_trace(ew3, transfer_hash)
    check_opcode_trace_with_config(ew3, transfer_hash)

def check_deploy_trace(ew3, tx_hash):
    tx_trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash])
    oplog_len = len(tx_trace["structLogs"])
    assert tx_trace['failed'] == False
    assert tx_trace['gas'] > 21000
    assert oplog_len > 0
    
    # key check
    keys = ["pc", "op", "gas", "gasCost", "depth", "stack"]
    for key in keys:
        assert key in tx_trace['structLogs'][0]

    assert tx_trace["structLogs"][oplog_len-1]["op"] == "RETURN"

def check_transfer_trace(ew3, transfer_hash):
    transfer_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash])

    assert transfer_trace["failed"] == False
    oplog_len = len(transfer_trace["structLogs"])
    assert oplog_len > 0
    assert transfer_trace["structLogs"][oplog_len-1]["op"] == "RETURN"

    

def check_noop_trace(ew3, transfer_hash):
    noop_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash, {"tracer": "noopTracer"}])
    assert noop_trace == {}

def check_four_byte_trace(ew3, transfer_hash):
    four_byte_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash, {"tracer": "4byteTracer"}])
    assert four_byte_trace == {'0xa9059cbb-64': 1}

def check_call_trace(ew3, transfer_hash):
    call_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash, {"tracer": "callTracer"}])
    assert call_trace["from"] == "0x0e768d12395c8abfdedf7b1aeb0dd1d27d5e2a7f"
    assert call_trace["to"] == "0xe2182fba747b5706a516d6cf6bf62d6117ef86ea"
    assert call_trace["type"] == 'CALL'
    assert call_trace["value"] == "0x0"
    assert call_trace["output"] == "0x0000000000000000000000000000000000000000000000000000000000000001"

def check_opcode_trace_with_config(ew3, tx_hash):
    trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash, {
        "enableMemory": True,
        "disableStack": False,
        "disableStorage": False,
        "enableReturnData": True
    }])

    oplog_len = len(trace["structLogs"])
    assert trace["failed"] == False
    assert oplog_len == 304

    # limit parameter test
    limited_trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash, {
        "enableMemory": True,
        "disableStack": False,
        "disableStorage": False,
        "enableReturnData": True,
        "limit": 10
    }])
    assert len(limited_trace["structLogs"]) == 10

    no_stack_storage_trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash, {
        "enableMemory": True,
        "disableStack": True,
        "disableStorage": True,
        "enableReturnData": True
    }])

    disable_all_trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash, {
        "enableMemory": False,
        "disableStack": True,
        "disableStorage": True,
        "enableReturnData": False
    }])

    for i, oplog in enumerate(trace["structLogs"]):
        oplog = trace["structLogs"][i]
        
        if "memory" in oplog:
            assert "memory" not in disable_all_trace["structLogs"][i]

        if "returnData" in oplog:
            assert "returnData" not in disable_all_trace["structLogs"][i]
        
        if "stack" in oplog:
            assert "stack" not in no_stack_storage_trace["structLogs"][i]
        
        if "storage" in oplog:
            assert "storage" not in no_stack_storage_trace["structLogs"][i]
