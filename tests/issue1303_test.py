#!/usr/bin/env python3

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import assert_equal

FULLNODE0 = 0
FORK_LENGTH = 100

class Issue1303Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        self.start_node(FULLNODE0, ["--archive"])

        # set up RPC client
        self.rpc = RpcClient(self.nodes[FULLNODE0])

        # wait for phase changes to complete
        self.nodes[FULLNODE0].wait_for_phase(["NormalSyncPhase"])

    def run_test(self):
        # send tx0 to a random account
        (addr, _) = self.rpc.rand_account()
        tx0 = self.rpc.new_tx(value=5 * 10 ** 18, receiver=addr, nonce=0)
        assert_equal(self.rpc.send_tx(tx0, wait_for_receipt=True), tx0.hash_hex())

        fork_hash = self.nodes[FULLNODE0].best_block_hash()

        # send tx1 to a random account
        (addr, _) = self.rpc.rand_account()
        tx1 = self.rpc.new_tx(value=5 * 10 ** 18, receiver=addr, nonce=1)
        assert_equal(self.rpc.send_tx(tx1, wait_for_receipt=True), tx1.hash_hex())

        tip0 = self.nodes[FULLNODE0].best_block_hash()

        # current ledger:
        # x -- x -- x -- tx0 -- x -- x -- x -- tx1 -- tip0

        # check receipts before fork
        r0 = self.rpc.get_transaction_receipt(tx0.hash_hex())
        assert(r0 != None)

        r1 = self.rpc.get_transaction_receipt(tx1.hash_hex())
        assert(r1 != None)

        r1_original_epoch = r1["epochNumber"]

        # create fork
        tip1 = self.generate_chain(fork_hash, FORK_LENGTH)[-1]

        # current ledger:
        # x -- x -- x -- tx0 -- x -- x -- x -- tx1 -- tip0
        #                             \
        #                              \-- x -- x -- x -- x -- x -- tip1

        # check receipts after fork
        r0 = self.rpc.get_transaction_receipt(tx0.hash_hex())
        assert(r0 != None)

        r1 = self.rpc.get_transaction_receipt(tx1.hash_hex())
        assert(r1 == None) # fails before #1303

        # connect forks, tx should be re-executed
        tip = self.rpc.generate_block_with_parent(tip1, referee = [tip0])

        # this time, tx1 will be in the epoch of `tip`
        # we need at least DEFERRED more blocks before it is re-executed
        tip = self.generate_chain(tip, 5)[-1]

        # current ledger:
        # x -- x -- x -- tx0 -- x -- x -- x -- tx1 -- tip0 ..................
        #                             \                                     :
        #                              \-- x -- x -- x -- x -- x -- tip1 -- x -- x -- x -- x -- x -- tip

        # check if updated receipt exists
        r1 = self.rpc.get_transaction_receipt(tx1.hash_hex())
        assert(r1 != None)
        assert(r1["epochNumber"] > r1_original_epoch)

        self.log.info(f"Pass")

    def generate_chain(self, parent, len):
        hashes = [parent]
        for _ in range(len):
            hash = self.rpc.generate_block_with_parent(hashes[-1])
            hashes.append(hash)
        return hashes[1:]

if __name__ == "__main__":
    Issue1303Test().main()
