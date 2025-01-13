from integration_tests.test_framework.util import *

def test_tx_and_receipt(ew3, erc20_contract, evm_accounts, network, cross_space_transfer):
    new_account = ew3.eth.account.create()
    cross_space_transfer(new_account.address, 1 * 10 ** 18)
    ret = network.nodes[0].debug_getTransactionsByEpoch("0x1")
    assert_equal(len(ret), 1)