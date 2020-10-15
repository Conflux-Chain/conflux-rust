#!/usr/bin/env python3
"""An example functional test
"""
from conflux.rpc import RpcClient
from conflux.utils import ec_random_keys, priv_to_addr
from test_framework.mininode import start_p2p_connection
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class ZeroGasPriceTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        STATUS_SUCCESS = "0x0"
        STATUS_EXCEPTION_WITH_NONCE_BUMP = "0x1"
        STATUS_EXCEPTION_WITHOUT_NONCE_BUMP = "0x2"
        rpc_cient = RpcClient(self.nodes[0])
        sk1, pk1 = ec_random_keys()
        address1 = priv_to_addr(sk1)

        # Successful payment
        tx = rpc_cient.new_tx(gas_price=0, receiver=address1, value=42000)
        rpc_cient.generate_block_with_fake_txs([tx])
        rpc_cient.wait_for_receipt(tx.hash_hex())
        receipt = rpc_cient.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], STATUS_SUCCESS)

        # Not enough cash
        tx = rpc_cient.new_tx(gas_price=0, priv_key=sk1, value=42001)
        rpc_cient.generate_block_with_fake_txs([tx])
        rpc_cient.wait_for_receipt(tx.hash_hex())
        receipt = rpc_cient.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], STATUS_EXCEPTION_WITH_NONCE_BUMP)
        print(receipt["txExecErrorMsg"])


if __name__ == '__main__':
    ZeroGasPriceTest().main()
