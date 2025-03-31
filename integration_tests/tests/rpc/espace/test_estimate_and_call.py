from integration_tests.test_framework.util import load_contract_metadata, assert_raises_web3_rpc_error

def test_estimate_and_call_basic(ew3, evm_accounts, network):
    call_request = {
        "to": ew3.to_checksum_address("0x007a026f3fe3c8252f0adb915f0d924aef942f53"),
        "value": "0x100",
        "chainId": ew3.to_hex(network.nodes[0].chain_id)
    }
    estimate_result = ew3.eth.estimate_gas(call_request)
    assert estimate_result == 21000

    call_result = ew3.eth.call(call_request)
    assert call_result.to_0x_hex() == "0x"

    new_account = ew3.eth.account.create()

    call_request["from"] = new_account.address
    assert_raises_web3_rpc_error(-32000, "SenderDoesNotExist", ew3.eth.estimate_gas, call_request)
    assert_raises_web3_rpc_error(-32000, "SenderDoesNotExist", ew3.eth.call, call_request)

def test_revert(ew3):
    contract_meta = load_contract_metadata("Error")
    abi = contract_meta['abi']
    ErrorContract = ew3.eth.contract(abi=contract_meta['abi'], bytecode=contract_meta['bytecode'])
    tx_hash = ErrorContract.constructor().transact()
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    
    deploy_receipt = ew3.eth.get_transaction_receipt(tx_hash)
    assert deploy_receipt["status"] == 1
    addr = deploy_receipt["contractAddress"]

    err_contract = ew3.eth.contract(address=addr, abi=abi)

    data = err_contract.encode_abi(abi_element_identifier="testRequire", args=[1])
    call_request = {
        "to": addr,
        "data": data,
    }
    err_msg = "execution reverted: revert: Input must be greater than 10"
    err_data = "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001d496e707574206d7573742062652067726561746572207468616e203130000000"

    assert_raises_web3_rpc_error(3, err_msg, ew3.eth.estimate_gas, call_request, err_data_=err_data)
    assert_raises_web3_rpc_error(3, err_msg, ew3.eth.call, call_request, err_data_=err_data)

    data = err_contract.encode_abi(abi_element_identifier="testRevert", args=[1])
    call_request = {
        "to": addr,
        "data": data,
    }

    assert_raises_web3_rpc_error(3, err_msg, ew3.eth.estimate_gas, call_request, err_data_=err_data)
    assert_raises_web3_rpc_error(3, err_msg, ew3.eth.call, call_request, err_data_=err_data)

    data = err_contract.encode_abi(abi_element_identifier="testCustomError", args=[1])
    call_request = {
        "to": addr,
        "data": data,
    }

    custom_err_msg = "execution reverted: revert:"
    custom_err_data = "0xcf47918100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"

    try:
        ew3.manager.request_blocking('eth_estimateGas', [call_request])
    except Exception as e:
        assert custom_err_msg in e.rpc_response['error']['message']
        assert e.rpc_response['error']['code'] == 3
        assert e.rpc_response['error']['data'] == custom_err_data
    try:
        ew3.manager.request_blocking('eth_call', [call_request])
    except Exception as e:
        assert custom_err_msg in e.rpc_response['error']['message']
        assert e.rpc_response['error']['code'] == 3
        assert e.rpc_response['error']['data'] == custom_err_data

def test_eth_call_unkown_field(ew3):
    call_request = {
        "accessList": [],
        "unkown": [],
    }
    ew3.eth.call(call_request)

def test_eth_call_zero_balance_sender(ew3):
    new_account = ew3.eth.account.create()
    call_request = {
        "from": new_account.address,
    }
    ew3.eth.call(call_request)
