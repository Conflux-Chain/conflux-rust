from typing import List

from eth_account.datastructures import SignedTransaction


def _sign_legacy_transfer(ew3, sender, to_address: str, nonce: int) -> SignedTransaction:
    return sender.sign_transaction(
        {
            "to": to_address,
            "value": 1,
            "gas": 21000,
            "gasPrice": 1,
            "nonce": nonce,
            "chainId": ew3.eth.chain_id,
        }
    )


def test_eth_get_block_transaction_count_by_hash_multi_txs(ew3, evm_accounts, network):
    sender = evm_accounts[0]
    receiver = ew3.eth.account.create().address
    base_nonce = ew3.eth.get_transaction_count(sender.address)

    signed_txs: List[SignedTransaction] = [
        _sign_legacy_transfer(ew3, sender, receiver, base_nonce),
        _sign_legacy_transfer(ew3, sender, receiver, base_nonce + 1),
    ]

    parent_hash = network.rpc.block_by_epoch("latest_mined")["hash"]
    block_hash = network.rpc.generate_custom_block(
        parent_hash=parent_hash,
        referee=[],
        txs=[tx.raw_transaction for tx in signed_txs],
    )

    # Ensure the block is executed/available in eSpace RPC.
    parent = block_hash
    for _ in range(5):
        parent = network.rpc.generate_custom_block(parent_hash=parent, referee=[], txs=[])

    block = ew3.eth.get_block(block_hash)
    tx_count = ew3.eth.get_block_transaction_count(block_hash)

    assert tx_count == 2
    assert len(block["transactions"]) == 2
    for tx in signed_txs:
        assert tx.hash in block["transactions"]
