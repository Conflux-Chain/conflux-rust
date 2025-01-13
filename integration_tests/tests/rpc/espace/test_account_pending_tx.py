
def test_account_pending_tx(ew3, evm_accounts):
    account = evm_accounts[0]
    new_account = ew3.eth.account.create()

    tx_hash = ew3.eth.send_transaction({
        "from": account.address,
        "to": new_account.address,
        "value": ew3.to_wei(1, "ether"),
    })
    ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert ew3.eth.get_balance(new_account.address) == ew3.to_wei(1, "ether")

    signed_tx = ew3.eth.account.sign_transaction({
        "from": new_account.address,
        "to": account.address,
        "value": 1,
        "nonce": 2,
        "gas": 21000,
        "gasPrice": ew3.to_wei('50', 'gwei')
    }, new_account.key)

    raw_tx = signed_tx.raw_transaction.hex()

    tx_hash = ew3.eth.send_raw_transaction(raw_tx)

    pending_txs = ew3.manager.request_blocking('eth_getAccountPendingTransactions', [new_account.address])
    assert pending_txs['pendingCount'] == '0x1'
    assert pending_txs['firstTxStatus']['pending'] == 'futureNonce'
    assert pending_txs['pendingTransactions'][0]['nonce'] == '0x2'
    assert pending_txs['pendingTransactions'][0]['blockHash'] is None
    assert pending_txs['pendingTransactions'][0]['status'] is None