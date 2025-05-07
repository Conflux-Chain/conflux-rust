import pytest
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    sign_eip7702_transaction,
    Authorization,
    EIP7702Transaction
)

# Test private key (DO NOT USE IN PRODUCTION)
TEST_PRIVATE_KEY = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'

@pytest.fixture
def authorization() -> Authorization:
    contract_address = '0x1234567890123456789012345678901234567890'
    chain_id = 1
    nonce = 0
    
    result = sign_authorization(
        contract_address=contract_address,
        chain_id=chain_id,
        nonce=nonce,
        private_key=TEST_PRIVATE_KEY
    )
    return result

def test_sign_authorization(authorization: Authorization):
    assert authorization.chainId == 1
    assert authorization.nonce == 0
    assert authorization.contractAddress == '0x1234567890123456789012345678901234567890'
    assert isinstance(authorization, Authorization)

def test_sign_eip7702_transaction(authorization: Authorization):
    transaction: EIP7702Transaction = {
        'authorizationList': [authorization],
        'chainId': 1,
        'gas': 21000,
        'nonce': 0,
        'to': '0x1234567890123456789012345678901234567890',
        'value': 0,
        'maxFeePerGas': 1000000000,
        'maxPriorityFeePerGas': 100000000,
        'data': '0x'
    }
    
    result = sign_eip7702_transaction(transaction, TEST_PRIVATE_KEY)
    
    assert isinstance(result, bytes)
