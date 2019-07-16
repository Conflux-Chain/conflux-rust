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
from scripts.exp_latency import pscp, pssh, kill_remote_conflux

class RemoteSimulate(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.rpc_timewait = 60
        self.num_nodes = 1
        self.conf_parameters = {
            "log_level": "\"debug\"",
            "fast_recover": "true",
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
        parser.add_argument(
            "--data-propagate-enabled",
            dest="data_propagate_enabled",
            action='store_true',
        )
        parser.add_argument(
            "--data-propagate-interval-ms",
            dest="data_propagate_interval_ms",
            default=1000,
            type=int
        )
        parser.add_argument(
            "--data-propagate-size",
            dest="data_propagate_size",
            default=1000,
            type=int
        )
        # Tx generation will also be enabled if we enable tx propagation
        parser.add_argument(
            "--enable-tx-propagation",
            dest="tx_propagation_enabled",
            action="store_true"
        )
        # options for LAT_LATEST
        parser.add_argument(
            "--tps",
            dest="tps",
            default=1000,
            type=int,
        )
        # Bandwidth in Mbit/s
        parser.add_argument(
            "--bandwidth",
            dest="bandwidth",
            default=20,
            type=int
        )
        # Peer propagation count
        parser.add_argument(
            "--min-peers-propagation",
            dest="min_peers_propagation",
            default=8,
            type=int,
        )
        parser.add_argument(
            "--max-peers-propagation",
            dest="max_peers_propagation",
            default=128,
            type=int,
        )
        parser.add_argument(
            "--send-tx-period-ms",
            dest="send_tx_period_ms",
            default=1300,
            type=int,
        )
        parser.add_argument(
            "--txgen-account-count",
            dest="txgen_account_count",
            default=1000,
            type=int,
        )

    def after_options_parsed(self):
        ConfluxTestFramework.after_options_parsed(self)

        self.num_nodes = self.options.nodes_per_host

        self.ips = []
        with open(self.options.ips_file, 'r') as ip_file:
            for line in ip_file.readlines():
                line = line[:-1]
                self.ips.append(line)

        # experiment name
        self.tx_propagation_enabled = self.options.tx_propagation_enabled

        # throttling
        egress_settings = self.options.throttling.split(",")
        self.conf_parameters["egress_queue_capacity"] = egress_settings[2]
        self.conf_parameters["egress_max_throttle"] = egress_settings[1]
        self.conf_parameters["egress_min_throttle"] = egress_settings[0]

        # target memory GB
        target_memory = 16

        # storage
        self.conf_parameters["ledger_cache_size"] = str(2000 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["db_cache_size"] = str(128 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["storage_cache_start_size"] = str(1000000 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["storage_cache_size"] = str(20000000 // target_memory * self.options.storage_memory_mb)
        # self.conf_parameters["storage_cache_size"] = "200000"
        self.conf_parameters["storage_idle_size"] = str(200000 // target_memory * self.options.storage_memory_mb)
        self.conf_parameters["storage_node_map_size"] = str(80000000 // target_memory * self.options.storage_memory_mb)

        # txpool
        self.conf_parameters["tx_pool_size"] = str(500000 // target_memory * self.options.storage_memory_mb)

        # data propagation
        self.conf_parameters["data_propagate_enabled"] = str(self.options.data_propagate_enabled).lower()
        self.conf_parameters["data_propagate_interval_ms"] = str(self.options.data_propagate_interval_ms)
        self.conf_parameters["data_propagate_size"] = str(self.options.data_propagate_size)

        # Do not keep track of tx address to save CPU/Disk costs because they are not used in the experiments
        self.conf_parameters["record_tx_address"] = "false"
        if self.tx_propagation_enabled:
            self.conf_parameters["generate_tx"] = "true"
            self.conf_parameters["generate_tx_period_us"] = str(1000000 * len(self.ips) // self.options.tps)
            self.conf_parameters["txgen_account_count"] = str(self.options.txgen_account_count)
        else:
            self.conf_parameters["send_tx_period_ms"] = "31536000000" # one year to disable txs propagation

        # tx propagation setting
        self.conf_parameters["min_peers_propagation"] = str(self.options.min_peers_propagation)
        self.conf_parameters["max_peers_propagation"] = str(self.options.max_peers_propagation)
        self.conf_parameters["send_tx_period_ms"] = str(self.options.send_tx_period_ms)

    def stop_nodes(self):
        kill_remote_conflux(self.options.ips_file)

    def setup_remote_conflux(self):
        # tar the config file for all nodes
        zipped_conf_file = os.path.join(self.options.tmpdir, "conflux_conf.tgz")
        with tarfile.open(zipped_conf_file, "w:gz") as tar_file:
            tar_file.add(self.options.tmpdir, arcname=os.path.basename(self.options.tmpdir))

        self.log.info("copy conflux configuration files to remote nodes ...")
        pscp(self.options.ips_file, zipped_conf_file, "~", 3, "copy conflux configuration files to remote nodes")
        os.remove(zipped_conf_file)

        # setup on remote nodes and start conflux
        self.log.info("setup conflux runtime environment and start conflux on remote nodes ...")
        cmd_kill_conflux = "killall -9 conflux || echo already killed"
        cmd_cleanup = "rm -rf /tmp/conflux_test_*"
        cmd_setup = "tar zxf conflux_conf.tgz -C /tmp"
        cmd_startup = "sh ./remote_start_conflux.sh {} {} {} {} &> start_conflux.out".format(
            self.options.tmpdir, p2p_port(0), self.options.nodes_per_host, self.options.bandwidth,
        )
        cmd = "{}; {} && {} && {}".format(cmd_kill_conflux, cmd_cleanup, cmd_setup, cmd_startup)
        pssh(self.options.ips_file, cmd, 3, "setup and run conflux on remote nodes")

    def setup_network(self):
        self.setup_remote_conflux()

        # add remote nodes and start all
        for ip in self.ips:
            self.add_remote_nodes(self.options.nodes_per_host, user="ubuntu", ip=ip)
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

        if self.tx_propagation_enabled:
            # Setup balance for each node
            client = RpcClient(self.nodes[0])
            for i in range(num_nodes):
                pub_key = self.nodes[i].key
                addr = self.nodes[i].addr
                self.log.info("%d has addr=%s pubkey=%s", i, encode_hex(addr), pub_key)
                tx = client.new_tx(value=int(default_config["TOTAL_COIN"]/(num_nodes + 1)) - 21000, receiver=encode_hex(addr), nonce=i)
                client.send_tx(tx)

        # setup monitor to report the current block count periodically
        cur_block_count = self.nodes[0].getblockcount()
        # The monitor will check the block_count of nodes[0]
        monitor_thread = threading.Thread(target=self.monitor, args=(cur_block_count, 100), daemon=True)
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
                    time.sleep(0.01)
                else:
                    break

            if retry >= 10:
                self.log.warn("too many nodes are busy to generate block, stop to analyze logs.")
                break

            if self.tx_propagation_enabled:
                # Generate a block with the transactions in the node's local tx pool
                thread = SimpleGenerateThread(self.nodes, p, self.options.txs_per_block, self.options.generate_tx_data_len, self.log, rpc_times)
            else:
                # Generate a fixed-size block with fake tx
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

        start = time.time()
        # Wait for at most 120 seconds
        while time.time() - start <= 120:
            block_counts = []
            best_blocks = []
            block_count_futures = []
            best_block_futures = []

            for i in range(len(self.nodes)):
                n = self.nodes[i]
                block_count_futures.append(executor.submit(n.getblockcount))
                best_block_futures.append(executor.submit(n.getbestblockhash))

            for f in block_count_futures:
                assert f.exception() is None, "failed to get block count: {}".format(f.exception())
                block_counts.append(f.result())
            max_count = max(block_counts)
            for i in range(len(block_counts)):
                if block_counts[i] < max_count - 50:
                    self.log.info("Slow: {}: {}".format(i, block_counts[i]))

            for f in best_block_futures:
                assert f.exception() is None, "failed to get best block: {}".format(f.exception())
                best_blocks.append(f.result())

            self.log.info("blocks: {}".format(Counter(block_counts)))

            if block_counts.count(block_counts[0]) == len(self.nodes) and best_blocks.count(best_blocks[0]) == len(self.nodes):
                break

            time.sleep(5)
        self.log.info("Goodput: {}".format(self.nodes[0].getgoodput()))
        executor.shutdown()

    def monitor(self, cur_block_count:int, retry_max:int):
        pre_block_count = 0

        retry = 0
        while pre_block_count < self.options.num_blocks + cur_block_count:
            time.sleep(self.options.generation_period_ms / 1000 / 2)

            # block count
            block_count = self.nodes[0].getblockcount()
            if block_count != pre_block_count:
                self.log.info("current blocks: %d", block_count)
                pre_block_count = block_count
                retry = 0
            else:
                retry += 1
                if retry >= retry_max:
                    self.log.error("No block generated after %d average block generation intervals", retry_max / 2)
                    break

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


class SimpleGenerateThread(GenerateThread):
    def run(self):
        try:
            client = RpcClient(self.nodes[self.i])
            # Do not limit num tx in blocks, only limit it with block size
            h = client.generate_block(10000000, self.tx_n * self.tx_data_len)
            self.log.debug("node %d actually generate block %s", self.i, h)
        except Exception as e:
            self.log.error("Node %d fails to generate block", self.i)
            self.log.error(str(e))


if __name__ == "__main__":
    RemoteSimulate().main()