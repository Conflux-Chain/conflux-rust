
def test_eth_call_support_both_data_and_input(erc20_contract, ew3, evm_accounts):
    erc20 = erc20_contract["contract"]

    new_account = ew3.eth.account.create()

    tx_hash = erc20.functions.transfer(new_account.address, ew3.to_wei(1, "ether")).transact({"from": evm_accounts[0].address})
    ew3.eth.wait_for_transaction_receipt(tx_hash)

    data = erc20.encode_abi(abi_element_identifier="balanceOf", args=[new_account.address])

    res1 = ew3.eth.call({
        "from": new_account.address,
        "to": erc20.address,
        "data": data,
    })

    res2 = ew3.eth.call({
        "from": new_account.address,
        "to": erc20.address,
        "input": data,
    })

    assert res1 == res2
    assert res1.hex() != "0000000000000000000000000000000000000000000000000000000000000000"

def test_empty_block_tx_root(ew3, network):
    empty_hash = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    block_number = ew3.eth.block_number
    network.rpc.generate_blocks(5) # need to generate a few more blocks to make the block_number + 1 available 
    # block_number2 = ew3.eth.block_number
    # print("block_number", block_number2)
    block = ew3.eth.get_block(block_number + 1)
    assert block["receiptsRoot"].to_0x_hex() == empty_hash
    assert block["transactionsRoot"].to_0x_hex() == empty_hash