from integration_tests.conflux.rpc import RpcClient
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
                self.log.debug("choose %d to generate block", r)
                h = self.clients[r].generate_block(self.num_txs)

                self.log.debug("%s generate block %s", r, h)
            except Exception as e:
                self.log.info("Node[%d] fails to generate blocks", r)
                self.log.info(e)

    def stop(self):
        self.stopped = True


class PoWGenerateThread(threading.Thread):
    def __init__(self, name, node, generation_period_ms, log, report_progress_blocks=None, fixed_period=False):
        threading.Thread.__init__(self, daemon=True)
        self.name = name
        self.node = node
        self.generation_period_ms = generation_period_ms
        self.log = log
        self.report_progress_blocks = report_progress_blocks
        self.fixed_period = fixed_period

    def generate_block(self):
        self.node.test_generateEmptyBlocks(1)

    def run(self):
        # generate blocks
        i = 0
        period_start_time = time.time()
        while True:
            i += 1
            if self.report_progress_blocks is not None:
                if i % self.report_progress_blocks == 0:
                    period_elapsed = time.time() - period_start_time
                    self.log.info("[%s]: %d blocks generated in %f seconds", self.name, self.report_progress_blocks, period_elapsed)
                    period_start_time = time.time()

            if self.fixed_period:
                wait_sec = self.generation_period_ms / 1000
            else:
                wait_sec = random.expovariate(1000 / self.generation_period_ms)
            start = time.time()
            self.generate_block()
            elapsed = time.time() - start
            if elapsed < wait_sec:
                time.sleep(wait_sec - elapsed)