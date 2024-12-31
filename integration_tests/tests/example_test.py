import pytest
from cfx_utils import CFX

@pytest.fixture(scope="module")
def additional_secrets():
    return 9

def test_secrets_count(additional_secrets, core_accounts, evm_accounts):
    assert len(core_accounts) == additional_secrets + 1
    assert len(evm_accounts) == additional_secrets + 1

def test_send_core_cfx(cw3, core_accounts):
    for account in core_accounts:
        to_address = cw3.cfx.account.create().address
        tx_hash = cw3.cfx.send_transaction({
            "to": to_address,
            "value": CFX(1),
            "from": account.address
        })
        tx_hash.executed()  # cw3.cfx.wait_for_transaction_receipt(tx_hash) also works
        assert cw3.cfx.get_balance(to_address) == CFX(1)

def test_send_evm_cfx(ew3, evm_accounts):
    for account in evm_accounts:
        to_address = ew3.eth.account.create().address
        tx_hash = ew3.eth.send_transaction({
            "to": to_address,
            "value": ew3.to_wei(1, "ether"),
            "from": account.address
        })
        ew3.eth.wait_for_transaction_receipt(tx_hash)
        assert ew3.eth.get_balance(to_address) == ew3.to_wei(1, "ether")
