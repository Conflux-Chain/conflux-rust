
def test_simulate_v1_basic(ew3, evm_accounts, network):
    sender1 = evm_accounts[0]
    sender2 = sender1
    chain_id = ew3.to_hex(network.nodes[0].chain_id)
    # construct request
    call_request = {
        "from": sender1.address,
        "to": ew3.to_checksum_address("0x007a026f3fe3c8252f0adb915f0d924aef942f53"),
        "value": "0x100",
        "chainId": chain_id
    }
    
    call_request2 = {
        "from": sender2.address,
        "to": ew3.to_checksum_address("0x007a026f3fe3c8252f0adb915f0d924aef942f53"),
        "value": "0x100",
        "chainId": chain_id
    }
    
    simulate_request = {
        "blockStateCalls": [
            {
                "calls": [call_request],
            },
            {
                "calls": [call_request2],
            },
        ],
        "traceTransfers": False,
        "validation": False,
        "returnFullTransactions": True,
    }
    # do request
    simulate_res = ew3.eth.simulate_v1(simulate_request, "latest")
    
    assert len(simulate_res) == 2
    assert len(simulate_res[0]["calls"]) == 1
    assert simulate_res[0]["calls"][0]["status"] == 1
    
    # check response