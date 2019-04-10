#!/usr/bin/env python3

from argparse import ArgumentParser
from eth_utils import decode_hex
from rlp.sedes import Binary, BigEndianInt

from conflux import utils
from conflux.utils import encode_hex, bytes_to_int, privtoaddr, parse_as_int, pubtoaddr
from test_framework.blocktools import create_block, create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

class P2PTest(ConfluxTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 7
        self.rpc_timewait = 3600
        self.conf_parameters = {
            "generate_tx": "true", "generate_tx_period_ms": "2", "log_level": "\"debug\"",
            "storage_cache_size": "20_000_000",
            "storage_cache_start_size": "20_000_000",
            "storage_node_map_size": "100_000_000",
            "tx_pool_size": "500000",
            "fast_recover": "true",
            # "enable_discovery": "true",
            #"node_table_timeout": "10",
            #"node_table_promotion_timeout": "10",
            #"bootnodes": "\'cfxnode://97f40043d42028ea5b4ea653981011fdf8c4e63c18089ea4b8ff9004ebc67873069ae8b745e238d9e150637acbfccb14e66e42d396fc7453e5b83fd5704d7141@54.219.149.90:32323\'",
            "start_mining": "false",
            "test_mode": "true",
        }

    def add_options(self, parser:ArgumentParser):
        parser.add_argument(
            "--nodes-per-host",
            dest="nodes_per_host",
            default=3,
            type=int
        )
        parser.add_argument(
            "--txs-per-block",
            dest="txs_per_block",
            default=16000,
            type=int
        )
        parser.add_argument(
            "--generation-period",
            dest="generation_period",
            default=1,
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

    def setup_network(self):
        with open(self.options.ips_file, 'r') as ip_file:
            for line in ip_file.readlines():
                line = line[:-1]
                self.add_remote_nodes(self.options.nodes_per_host, user="ubuntu", ip=line)
        for i in range(len(self.nodes)):
            self.log.info("Node "+str(i) + " bind to "+self.nodes[i].ip+":"+self.nodes[i].port)
        self.start_nodes()
        self.log.info("All nodes started, waiting to be connected")
        
        connect_sample_nodes(self.nodes, self.log)

        self.log.info("All nodes connected, waiting to sync")
        sync_blocks(self.nodes)

    def run_test(self):
        start_p2p_connection([self.nodes[0]], remote=True)

        num_nodes = len(self.nodes)

        for i in range(num_nodes):
            pub_key = self.nodes[i].key
            addr = self.nodes[i].addr
            self.log.info("%d has addr=%s pubkey=%s", i, encode_hex(addr), pub_key)
            init_tx = create_transaction(value=int(default_config["TOTAL_COIN"]/num_nodes), receiver=addr, nonce=i)
            self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[init_tx]))
        self.nodes[0].disconnect_p2ps()
        mining = False
        if mining:
            for i in range(1, 100000):
                count = i * 1000
                while True:
                    if self.nodes[0].getblockcount() > count:
                        for index in range(num_nodes):
                            self.log.info("Node %d has %d blocks", index, self.nodes[index].getblockcount())
                            self.log.info("Node %d has best block %s", index, self.nodes[index].cfx_getBestBlockHash())
                        self.log.info("%d blocks synced", count)
                        break
                    else:
                        time.sleep(60)
                        continue
        else:
            threads = {}
            for i in range(1, self.options.num_blocks):
                wait_sec = random.expovariate(1 / self.options.generation_period)
                p = random.randint(0, num_nodes - 1)
                self.log.debug("%d try to generate block", p)
                start = time.time()
                if threads.get(p) is not None:
                    threads[p].join()
                thread = GenerateThread(self.nodes, p, self.options.txs_per_block, self.log)
                thread.start()
                threads[p] = thread
                end = time.time()
                if end - start < wait_sec:
                    self.log.debug("%d generating block %s", p, str(end-start))
                    time.sleep(wait_sec - (end - start))
                else:
                    self.log.debug("%d generating block slowly %s", p, str(end-start))
                if i % self.options.block_sync_step == 0:
                    for t in threads.values():
                        t.join(60)
                    # wait_for_block_count(self.nodes[0], i)
                    while True:
                        try:
                            sync_blocks(self.nodes, timeout=60)
                            break
                        except Exception as e:
                            time.sleep(5)
                            self.log.warn(e)
                            continue
                    self.log.info("%d blocks generated and synced", self.nodes[0].getblockcount())
        self.log.info("Pass")


class GenerateThread(threading.Thread):
    def __init__(self, nodes, i, tx_n, log):
        threading.Thread.__init__(self, daemon=True)
        self.nodes = nodes
        self.i = i
        self.tx_n = tx_n
        self.log = log

    def run(self):
        try:
            h = self.nodes[self.i].generateoneblock(self.tx_n)
            self.log.debug("node %d actually generate block %s", self.i, h)
        except Exception as e:
            self.log.error("Node %d fails to generate block", self.i)
            self.log.error(str(e))


if __name__ == "__main__":
    P2PTest().main()