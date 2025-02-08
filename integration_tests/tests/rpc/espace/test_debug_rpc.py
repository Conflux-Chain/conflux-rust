def test_trace_simple_cfx_transfer(ew3, evm_accounts):
    account = evm_accounts[0]
    to_address = ew3.eth.account.create().address
    tx_hash = ew3.eth.send_transaction({
        "from": account.address,
        "to": to_address,
        "value": ew3.to_wei(1, "ether"),
    })
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert ew3.eth.get_balance(to_address) == ew3.to_wei(1, "ether")

    tx_trace = ew3.manager.request_blocking('debug_traceTransaction', [tx_hash])
    assert tx_trace['failed'] == False
    assert tx_trace['gas'] == 21000
    assert tx_trace['returnValue'] == ''
    assert len(tx_trace['structLogs']) == 0

def test_trace_deploy_contract(ew3, erc20_contract):
    tx_hash = erc20_contract["deploy_hash"]
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

def test_transfer_trace(ew3, erc20_token_transfer):
    transfer_hash = erc20_token_transfer["tx_hash"]
    transfer_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash])

    assert transfer_trace["failed"] == False
    oplog_len = len(transfer_trace["structLogs"])
    assert oplog_len > 0
    assert transfer_trace["structLogs"][oplog_len-1]["op"] == "RETURN"

def test_noop_trace(ew3, erc20_token_transfer):
    transfer_hash = erc20_token_transfer["tx_hash"]
    noop_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash, {"tracer": "noopTracer"}])
    assert noop_trace == {}

def test_four_byte_trace(ew3, erc20_token_transfer):
    transfer_hash = erc20_token_transfer["tx_hash"]
    four_byte_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash, {"tracer": "4byteTracer"}])
    assert four_byte_trace == {'0xa9059cbb-64': 1}

def test_call_trace(ew3, erc20_token_transfer):
    transfer_hash = erc20_token_transfer["tx_hash"]
    call_trace = ew3.manager.request_blocking('debug_traceTransaction', [transfer_hash, {"tracer": "callTracer"}])
    assert call_trace["from"] == "0x0e768d12395c8abfdedf7b1aeb0dd1d27d5e2a7f"
    # assert call_trace["to"] == "0xe2182fba747b5706a516d6cf6bf62d6117ef86ea"
    assert call_trace["type"] == 'CALL'
    assert call_trace["value"] == "0x0"
    assert call_trace["output"] == "0x0000000000000000000000000000000000000000000000000000000000000001"

def test_opcode_trace_with_config(ew3, erc20_token_transfer):
    tx_hash = erc20_token_transfer["tx_hash"]
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
