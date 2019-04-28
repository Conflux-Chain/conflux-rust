#!/usr/bin/env python3

from argparse import ArgumentParser
from collections import Counter
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt
import tarfile
from concurrent.futures import ThreadPoolExecutor

from conflux import utils
from conflux.rpc import RpcClient
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int, pubtoaddr
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from scripts.stat_latency_map_reduce import Statistics

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.rpc_timewait = 30
        self.conf_parameters = {
            "log_level": "\"info\"",
            "fast_recover": "true",
            "enable_discovery": "false",
            "start_mining": "false",
            "test_mode": "true",
            "send_tx_period_ms": "31536000000", # one year to disable txs propagation
        }

    def add_options(self, parser:ArgumentParser):
        parser.add_argument(
            "--nodes-per-host",
            dest="nodes_per_host",
            default=3,
            type=int
        )
        parser.add_argument(
            "--generation-period-ms",
            dest="generation_period_ms",
            default=5000,
            type=int
        )
        parser.add_argument(
            "--num-blocks",
            dest="num_blocks",
            default=100,
            type=int
        )
        parser.add_argument(
            "--block-sync-step",
            dest="block_sync_step",
            default=10,
            type=int
        )
        parser.add_argument(
            "--ips-file",
            dest="ips_file",
            default="ips",
            type=str
        )
        parser.add_argument(
            "--txs-per-block",
            dest="txs_per_block",
            default=5,
            type=int
        )
        parser.add_argument(
            "--generate-tx-data-len",
            dest="generate_tx_data_len",
            default=0,
            type=int
        )
        parser.add_argument(
            "--connect-peers",
            dest="connect_peers",
            default=3,
            type=int
        )
        parser.add_argument(
            "--throttling",
            dest="throttling",
            default="512,1024,2048",
            type=str
        )
        parser.add_argument(
            "--storage-memory-mb",
            dest="storage_memory_mb",
            default=2,
            type=int
        )

    def after_options_parsed(self):
        self.num_nodes = self.options.nodes_per_host

        # throttling
        egress_settings = self.options.throttling.split(",")
        self.conf_parameters["egress_queue_capacity"] = egress_settings[2]
        self.conf_parameters["egress_max_throttle"] = egress_settings[1]
        self.conf_parameters["egress_min_throttle"] = egress_settings[0]

        # target memory GB
        target_memory = 16

        # storage
        self.conf_parameters["ledger_cache_size"] = str(2048 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["db_cache_size"] = str(128 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["storage_cache_start_size"] = str(1000000 // target_memory * self.options.storage_memory_mb)
        # self.conf_parameters["storage_cache_size"] = str(20000000 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["storage_cache_size"] = "200000"
        self.conf_parameters["storage_idle_size"] = str(200000 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["storage_node_map_size"] = str(80000000 // target_memory * self.options.storage_memory_mb)

        # txpool
        self.conf_parameters["tx_pool_size"] = str(500000 // target_memory * self.options.storage_memory_mb)

    def stop_nodes(self):
        result = self.__pssh__("killall -9 conflux")
        if result != 0:
            self.log.error("failed to kill conflux process on remote nodes, return code = {}".format(result))

    def __execute__(self, command):
        self.log.info("[COMMAND]: {}".format(command))
        result = os.system(command)
        if result != 0:
            self.log.error("command execution failed, return code is {}".format(result))
        return result

    def __pscp__(self, local:str, remote:str):
        cmd = 'parallel-scp -O "StrictHostKeyChecking no" -h {} -p 400 {} {}'.format(self.options.ips_file, local, remote)
        return self.__execute__(cmd)

    def __pssh__(self, cmd:str):
        cmd = 'parallel-ssh -O "StrictHostKeyChecking no" -h {} -p 400 \"{}\"'.format(self.options.ips_file, cmd)
        return self.__execute__(cmd)

    def setup_remote_conflux(self):
        # tar the config file for all nodes
        zipped_conf_file = os.path.join(self.options.tmpdir, "conflux_conf.tgz")
        with tarfile.open(zipped_conf_file, "w:gz") as tar_file:
            tar_file.add(self.options.tmpdir, arcname=os.path.basename(self.options.tmpdir))

        self.log.info("copy conflux configuration files to remote nodes ...")
        result = self.__pscp__(zipped_conf_file, "~")
        os.remove(zipped_conf_file)
        assert_equal(result, 0)

        self.log.info("setup conflux runtime environment ...")
        result = self.__pssh__("tar zxf conflux_conf.tgz -C /tmp && rm conflux_conf.tgz")
        assert_equal(result, 0)

        # start conflux on all nodes
        self.log.info("start conflux on remote nodes ...")
        result = self.__pssh__("./remote_start_conflux.sh {} {} {} > start_conflux.out".format(
            self.options.tmpdir, p2p_port(0), self.options.nodes_per_host
        ))
        assert_equal(result, 0)

    def setup_network(self):
        self.setup_remote_conflux()

        # add remote nodes and start all
        with open(self.options.ips_file, 'r') as ip_file:
            for line in ip_file.readlines():
                line = line[:-1]
                self.add_remote_nodes(self.options.nodes_per_host, user="ubuntu", ip=line)
        for i in range(len(self.nodes)):
            self.log.info("Node[{}]: ip={}, p2p_port={}, rpc_port={}".format(
                i, self.nodes[i].ip, self.nodes[i].port, self.nodes[i].rpcport))
        self.log.info("Starting remote nodes ...")
        self.start_nodes()
        self.log.info("All nodes started, waiting to be connected")

        connect_sample_nodes(self.nodes, self.log, sample=self.options.connect_peers, timeout=120)

        self.sync_blocks()

    def run_test(self):
        num_nodes = len(self.nodes)

        # setup monitor to report the current block count periodically
        cur_block_count = self.nodes[0].getblockcount()
        monitor_thread = threading.Thread(target=self.monitor, args=(cur_block_count,), daemon=True)
        monitor_thread.start()

        # generate blocks
        threads = {}
        rpc_times = []
        for i in range(1, self.options.num_blocks + 1):
            wait_sec = random.expovariate(1000 / self.options.generation_period_ms)
            start = time.time()
            
            # find an idle node to generate block
            p = random.randint(0, num_nodes - 1)
            retry = 0
            while retry < 10:
                pre_thread = threads.get(p)
                if pre_thread is not None and pre_thread.is_alive():
                    p = random.randint(0, num_nodes - 1)
                    retry += 1
                else:
                    break

            if retry >= 10:
                self.log.warn("too many nodes are busy to generate block, stop to analyze logs.")
                break

            thread = GenerateThread(self.nodes, p, self.options.txs_per_block, self.options.generate_tx_data_len, self.log, rpc_times)
            thread.start()
            threads[p] = thread

            if i % self.options.block_sync_step == 0:
                self.log.info("[PROGRESS] %d blocks generated async", i)

            elapsed = time.time() - start
            if elapsed < wait_sec:
                self.log.debug("%d generating block %.2f", p, elapsed)
                time.sleep(wait_sec - elapsed)
            else:
                self.log.warn("%d generating block slowly %.2f", p, elapsed)

        monitor_thread.join()
        self.sync_blocks()

        self.log.info("generateoneblock RPC latency: {}".format(Statistics(rpc_times, 3).__dict__))
        self.log.info("Best block: {}".format(RpcClient(self.nodes[0]).best_block_hash()))

    def sync_blocks(self):
        self.log.info("wait for all nodes to sync blocks ...")

        executor = ThreadPoolExecutor()

        while True:
            block_counts = []
            best_blocks = []
            block_count_futures = []
            best_block_futures = []

            for i in range(len(self.nodes)):
                n = self.nodes[i]
                block_count_futures.append(executor.submit(n.getblockcount))
                best_block_futures.append(executor.submit(n.getbestblockhash))

            for f in block_count_futures:
                if f.exception() is not None:
                    self.log.error("failed to get block count: {}".format(f.exception()))
                else:
                    block_counts.append(f.result())

            for f in best_block_futures:
                if f.exception() is not None:
                    self.log.error("failed to get best block: {}".format(f.exception()))
                else:
                    best_blocks.append(f.result())

            self.log.info("blocks: {}".format(Counter(block_counts)))

            if block_counts.count(block_counts[0]) == len(self.nodes) and best_blocks.count(best_blocks[0]) == len(self.nodes):
                break

            time.sleep(5)

        executor.shutdown()

    def monitor(self, cur_block_count:int):
        pre_block_count = 0

        while pre_block_count < self.options.num_blocks + cur_block_count:
            time.sleep(self.options.generation_period_ms / 1000 / 2)

            # block count
            block_count = self.nodes[0].getblockcount()
            if block_count != pre_block_count:
                self.log.info("current blocks: %d", block_count)
                pre_block_count = block_count

        self.log.info("monitor completed.")

class GenerateThread(threading.Thread):
    def __init__(self, nodes, i, tx_n, tx_data_len, log, rpc_times:list):
        threading.Thread.__init__(self, daemon=True)
        self.nodes = nodes
        self.i = i
        self.tx_n = tx_n
        self.tx_data_len = tx_data_len
        self.log = log
        self.rpc_times = rpc_times

    def run(self):
        try:
            client = RpcClient(self.nodes[self.i])
            txs = []
            for i in range(self.tx_n):
                addr = client.rand_addr()
                tx_gas = client.DEFAULT_TX_GAS + 4 * self.tx_data_len
                tx = client.new_tx(receiver=addr, nonce=10000+i, value=0, gas=tx_gas, data=b'\x00' * self.tx_data_len)
                # remove big data field and assemble on full node to reduce network load.
                tx.__dict__["data"] = b''
                txs.append(tx)
            encoded_txs = eth_utils.encode_hex(rlp.encode(txs))

            start = time.time()
            h = self.nodes[self.i].test_generateblockwithfaketxs(encoded_txs, self.tx_data_len)
            self.rpc_times.append(round(time.time() - start, 3))
            self.log.debug("node %d actually generate block %s", self.i, h)
        except Exception as e:
            self.log.error("Node %d fails to generate block", self.i)
            self.log.error(str(e))


if __name__ == "__main__":
    P2PTest().main()