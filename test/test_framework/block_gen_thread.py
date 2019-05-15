from conflux.rpc import RpcClient
import random
import time
import threading

class BlockGenThread(threading.Thread):
    def __init__(self, nodes, log, num_txs=1000, interval_fixed=None, interval_base=1):
        threading.Thread.__init__(self, daemon=True)
        self.nodes = nodes
        self.clients = []
        for node in nodes:
            self.clients.append(RpcClient(node))
        self.log = log
        self.num_txs = num_txs
        self.interval_fixed = interval_fixed
        self.interval_base = interval_base

        self.local_random = random.Random()
        self.local_random.seed(random.random())
        self.stopped = False

    def run(self):
        while not self.stopped:
            try:
                if self.interval_fixed is None:
                    time.sleep(self.local_random.random() * self.interval_base)
                else:
                    time.sleep(self.interval_fixed)

                r = self.local_random.randint(0, len(self.nodes) - 1)
                h = self.clients[r].generate_block(self.num_txs)

                self.log.debug("%s generate block %s", r, h)
            except Exception as e:
                self.log.info("Node[%d] fails to generate blocks", r)
                self.log.info(e)

    def stop(self):
        self.stopped = True
