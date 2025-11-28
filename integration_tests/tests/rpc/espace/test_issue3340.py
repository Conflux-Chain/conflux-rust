"""
Test for issue #3340: eth_estimateGas should return 
"insufficient funds for transfer" instead of "SenderDoesNotExist"
when the account has no prior transactions and zero balance.
"""
import pytest
from integration_tests.test_framework.util import assert_raises_web3_rpc_error


def test_estimate_gas_insufficient_funds(ew3):
    """
    Test that eth_estimateGas returns InsufficientFunds error
    instead of SenderDoesNotExist when account has zero balance.
    
    This matches Ethereum's behavior where any account (even non-existent)
    trying to send more than it has results in "insufficient funds" error.
    """
    # Create a new account that has never been used
    new_account = ew3.eth.account.create()
    
    # Verify the account has zero balance
    balance = ew3.eth.get_balance(new_account.address)
    assert balance == 0, "Account should have zero balance"
    
    # Create another account as recipient
    recipient = ew3.eth.account.create()
    
    # Try to estimate gas for a transaction from account with no balance
    # This should return "insufficient funds" error (code -32000)
    call_request = {
        "from": new_account.address,
        "to": recipient.address,
        "value": 10000000000000000,  # 0.01 ETH
    }
    
    # The error should be InsufficientFunds (indicated by the error message)
    # not SenderDoesNotExist
    with pytest.raises(Exception) as exc_info:
        ew3.eth.estimate_gas(call_request)
    
    error_message = str(exc_info.value)
    
    # Verify the error does not contain "SenderDoesNotExist"
    assert "SenderDoesNotExist" not in error_message, \
        f"Error should not contain 'SenderDoesNotExist', got: {error_message}"
    
    # Verify the error contains "insufficient funds"
    assert "insufficient funds" in error_message.lower(), \
        f"Error should contain 'insufficient funds', got: {error_message}"
