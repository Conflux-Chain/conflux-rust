import random
import threading
import time

from conflux.rpc import RpcClient
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.util import assert_equal

class TxPropagationTest(DefaultConfluxTestFramework):
    def run_test(self):
        # randomly select node to send tx
        self.log.info("begin to send 1000 txs to nodes randomly ...")
        txs = []
        for tx in self.generate_txs(1000):
            node_idx = random.randint(0, self.num_nodes - 1)
            client = RpcClient(self.nodes[node_idx])
            tx_hash = client.send_tx(tx)
            assert_equal(tx_hash, tx.hash_hex())
            txs.append(tx_hash)

        # begin to check the tx propagation for all nodes
        self.log.info("start threads for all nodes to check whether txs are all received")
        threads = []
        start_time = time.time()
        for i in range(self.num_nodes):
            node = self.nodes[i]
            t = threading.Thread(target=self.wait_for_txs, args=(node, txs), daemon=True)
            threads.append(t)
            t.start()

        # txs should be propagated timely
        self.log.info("wait for nodes to check the received txs ...")
        timeout = 30
        for t in threads:
            t.join(timeout)
            assert not t.is_alive(), "Transactions are not propagated to all nodes in {} seconds".format(timeout)

        self.log.info("Transactions propagated to all nodes in %.2f seconds", time.time() - start_time)

    def wait_for_txs(self, node, txs):
        client = RpcClient(node)
        
        for tx_hash in txs:
            while client.get_tx(tx_hash) is None:
                time.sleep(0.3)

    def generate_txs(self, num_txs):
        txs = []

        client = RpcClient(self.nodes[0])
        cur_nonce = client.get_nonce(client.GENESIS_ADDR)

        for _ in range(num_txs):
            addr = client.rand_addr()
            tx = client.new_tx(receiver=addr, nonce=cur_nonce)
            txs.append(tx)
            cur_nonce += 1

        return txs

if __name__ == "__main__":
    TxPropagationTest().main()