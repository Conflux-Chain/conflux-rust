#!/usr/bin/env python3
"""An example functional test
"""
from eth_utils import keccak

from conflux.rpc import RpcClient
from conflux.utils import ec_random_keys, priv_to_addr, encode_hex
from rpc.test_contract import REVERT_MESSAGE_CONTRACT_PATH
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.blocktools import encode_hex_0x


class ZeroGasPriceTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters = {"log_level": '"trace"'}
        self.rpc_timewait = 600000

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        STATUS_SUCCESS = "0x0"
        STATUS_EXCEPTION_WITH_NONCE_BUMP = "0x1"
        rpc_client = RpcClient(self.nodes[0])
        sk1, pk1 = ec_random_keys()
        address1 = encode_hex(priv_to_addr(sk1))

        '''
        Successful payment
        '''
        tx = rpc_client.new_tx(gas_price=0, receiver=address1, value=42000)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.wait_for_receipt(tx.hash_hex())
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], STATUS_SUCCESS)

        '''
        Not enough cash
        '''
        tx = rpc_client.new_tx(gas_price=0, priv_key=sk1, sender=address1, value=42001)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.wait_for_receipt(tx.hash_hex())
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], STATUS_EXCEPTION_WITH_NONCE_BUMP)
        assert "NotEnoughCash" in receipt["txExecErrorMsg"]

        '''
        Old nonce
        '''
        tx = rpc_client.new_tx(nonce=0, gas_price=0, priv_key=sk1, sender=address1, value=0)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.generate_blocks_to_state()
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt, None)

        '''
        Invalid nonce
        '''
        tx = rpc_client.new_tx(nonce=3, gas_price=0, priv_key=sk1, sender=address1, value=0)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.generate_blocks_to_state()
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt, None)

        '''
        Invalid recipient (the address starts with 2)
        '''
        tx = rpc_client.new_tx(gas_price=0, priv_key=sk1, sender=address1, value=0, receiver="2"*40)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.generate_blocks_to_state()
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt, None)

        '''
        EpochHeightOutOfBound
        '''
        tx = rpc_client.new_tx(gas_price=0, priv_key=sk1, sender=address1, value=0, epoch_height=1000000)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.generate_blocks_to_state()
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt, None)

        '''
        VmError (Reverted)
        '''
        # deploy contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "rpc", REVERT_MESSAGE_CONTRACT_PATH)
        bytecode = open(bytecode_file).read()
        tx = rpc_client.new_contract_tx("", bytecode, storage_limit=200000)
        rpc_client.send_tx(tx, wait_for_receipt=True)
        contract_addr = rpc_client.get_tx(tx.hash_hex())["contractCreated"]
        # call contract to trigger revert
        tx = rpc_client.new_tx(gas_price=0, priv_key=sk1, sender=address1, value=0, data=keccak(b"foo()"),
                              receiver=contract_addr,  gas=100000)
        self.log.info("Tx hash: %s", tx.hash_hex())
        rpc_client.generate_block_with_fake_txs([tx])
        rpc_client.wait_for_receipt(tx.hash_hex())
        receipt = rpc_client.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], STATUS_EXCEPTION_WITH_NONCE_BUMP)
        assert "Vm reverted" in receipt["txExecErrorMsg"]

        # TODO NotEnoughCashFromSponsor not tested.
        '''
        ContractAddressConflict cannot be tested.
        '''


if __name__ == '__main__':
    ZeroGasPriceTest().main()
