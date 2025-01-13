
def test_out_of_balance(ew3, evm_accounts):
    account = evm_accounts[0]
    new_account = ew3.eth.account.create()

    nonce = ew3.eth.get_transaction_count(new_account.address)
    signed_tx = ew3.eth.account.sign_transaction({
        "from": new_account.address,
        "to": account.address,
        "value": 1,
        "nonce": nonce,
        "gas": 21000,
        "gasPrice": ew3.to_wei('50', 'gwei')
    }, new_account.key)

    raw_tx = signed_tx.raw_transaction.hex()

    try:
        ew3.eth.send_raw_transaction(raw_tx)
        AssertionError("expect out of balance error")
    except Exception as e:
        assert str(e) == "{'code': -32003, 'message': 'insufficient funds for transfer'}"
    