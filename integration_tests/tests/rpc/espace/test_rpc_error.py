from integration_tests.test_framework.util import *

# send tx rpc error tests

def test_valid_tx(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)

    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "maxFeePerGas": 1,
        "maxPriorityFeePerGas": 1,
        "gas": 21000,
        "nonce": nonce,
        "chainId": 10,
    })

    tx_hash = ew3.eth.send_raw_transaction(signed["raw_transaction"])
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    next_nonce = ew3.eth.get_transaction_count(account.address)
    assert_equal(next_nonce, nonce + 1)

    tx = ew3.eth.get_transaction(tx_hash)
    assert_equal(tx["nonce"], nonce)
    assert_equal(tx["type"], 2)

def test_invalid_chain_id(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
        
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 1,
        "gas": 21000,
        "nonce": nonce,
        "chainId": 100,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
    except Exception as e:
        assert_equal(str(e), "{'code': -32000, 'message': 'invalid chain ID'}")
        return


def test_nonce_too_low(ew3, evm_accounts, receiver_account):
    # send a tx to receiver account
    tx_hash = ew3.eth.send_transaction({
        "from": evm_accounts[0].address,
        "to": receiver_account.address,
        "value": 1,
    })
    ew3.eth.wait_for_transaction_receipt(tx_hash)


    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 1,
        "gas": 21000,
        "nonce": nonce - 1,
        "chainId": 10,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
    except Exception as e:
        assert_equal(str(e), "{'code': -32003, 'message': 'nonce too low'}")
        return

def test_nonce_too_high(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 1,
        "gas": 21000,
        "nonce": nonce + 2000,
        "chainId": 10,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
    except Exception as e:
        assert_equal(str(e), "{'code': -32003, 'message': 'nonce too high'}")
        return

def test_same_nonce_higher_gas_price_required(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 1,
        "gas": 21000,
        "nonce": nonce,
        "chainId": 10,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
        time.sleep(1)
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
    except Exception as e:
        assert_equal(str(e), "{'code': -32603, 'message': 'already known'}")
        return

def test_gas_too_low(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 1,
        "gas": 2100,
        "nonce": nonce,
        "chainId": 10,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
    except Exception as e:
        assert_equal(str(e), "{'code': -32000, 'message': 'intrinsic gas too low'}")
        return

def test_gas_too_high(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
        
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 1,
        "gas": 40000000,
        "nonce": nonce,
        "chainId": 10,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
        # AssertionError("send tx failed")
    except Exception as e:
        assert_equal(str(e), "{'code': -32603, 'message': 'exceeds block gas limit'}")
        return

def test_zero_gas_price(ew3, evm_accounts):
    account = evm_accounts[0]
    nonce = ew3.eth.get_transaction_count(account.address)
    signed = account.sign_transaction({
        "to": account.address,
        "value": 1,
        "gasPrice": 0,
        "gas": 21000,
        "nonce": nonce,
        "chainId": 10,
    })

    try:
        ew3.eth.send_raw_transaction(signed["raw_transaction"])
    except Exception as e:
        assert_equal(str(e), "{'code': -32603, 'message': 'transaction underpriced'}")
        return
