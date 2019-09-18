#!/usr/bin/env python3
import datetime
import math

import numpy
from eth_utils import decode_hex

from test_framework.blocktools import create_transaction
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *


class RlpIter:
    BUFFER_SIZE = 1000000

    def __init__(self, f, batch_size):
        self.f = f
        self.bytes = bytearray()
        self.eof = False
        self.offset = 0
        self.batch_size = batch_size

    def __iter__(self):
        return self

    def __next__(self):
        length = len(self.bytes)
        if not self.eof and length < RlpIter.BUFFER_SIZE * 2:
            to_append = self.f.read(RlpIter.BUFFER_SIZE * 2 - length)
            self.eof = len(to_append) == 0
            self.bytes += to_append
            length = len(self.bytes)
        if length > 0:
            old_offset = self.offset
            txs = 0
            for i in range(0, self.batch_size):
                try:
                    (prefix, _type, length, end) = rlp.codec.consume_length_prefix(
                        self.bytes, self.offset
                    )
                    self.offset += len(prefix) + length
                    txs += 1
                except Exception as e:
                    print("error parsing rlp: %s.", e)
                    if self.offset == old_offset:
                        # We assume that a single transaction won't be larger than BUFFER_SIZE
                        raise e
            rlpbytes = self.bytes[old_offset: self.offset]
            if self.offset >= RlpIter.BUFFER_SIZE:
                self.bytes = self.bytes[RlpIter.BUFFER_SIZE:]
                self.offset -= RlpIter.BUFFER_SIZE
            return rlpbytes, txs
        else:
            raise StopIteration()


class ConfluxEthReplayTest(ConfluxTestFramework):
    # For eth + payments.
    # EXPECTED_TX_SIZE_PER_SEC = 250000
    # For eth replay
    EXPECTED_TX_SIZE_PER_SEC = 800000
    INITIALIZE_TXS = 200000 + 400 + 400
    INITIAL_SLEEP = 60
    GENESIS_KEY = decode_hex(
        "9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471"
    )
    TX_FILE = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "../../convert_eth_from_0_to_4141811_unknown_txs.rlp", )

    TOTAL_TX_NUMBER = 4000000

    def __init__(self):
        self.setup_clean_chain = True
        self.ips = []
        self.remote = True
        self.local_ip = []
        ConfluxTestFramework.__init__(self)

    def set_test_params(self):
        pass

    def setup_chain(self):
        if self.options.remote_ips != "":
            self.remote = True
        else:
            self.remote = False

        if self.remote:
            ips = []
            try:
                with open(self.options.remote_ips, "r") as ip_file:
                    for line in ip_file.readlines():
                        ips.append(line.strip().strip(","))
            except Exception:
                pass

            self.ips = ips
            self.num_nodes = len(ips)
        else:
            self.num_nodes = 1

        self.conf_parameters = {
            "log_level": '"debug"',
            # "storage_cache_start_size": "1000000",
            # Do not re-alloc.
            "eth_compatibility_mode": "true",
            "storage_cache_start_size": "20000000",
            "storage_cache_size": "20000000",
            "storage_idle_size": "2000000",
            "storage_node_map_size": "200000000",
            "ledger_cache_size": "3000",
            "send_tx_period_ms": "1300",
            "enable_discovery": "false",
            "egress_queue_capacity": "1024",
            "egress_min_throttle": "100",
            "egress_max_throttle": "1000",
            "tx_pool_size": "2000000",
            "block_db_type": '"rocksdb"',
            "no_defer": "false",
            "enable_optimistic_execution": "true",
        }
        self.initialize_chain_clean()

    def setup_network(self):
        if self.remote:
            binary_path = ["/home/ubuntu/conflux"]
            for ip in self.ips:
                self.add_remote_nodes(
                    1, user="ubuntu", ip=ip, binary=binary_path, no_pssh=True
                )
            for i in range(len(self.nodes)):
                self.log.info(
                    "Node "
                    + str(i)
                    + " bind to "
                    + self.nodes[i].ip
                    + ":"
                    + self.nodes[i].port
                )
            self.start_nodes()
            self.log.info("All nodes started, waiting to be connected")
            connect_sample_nodes(
                nodes=self.nodes, log=self.log, sample=7, latency_min=0, latency_max=300
            )
        else:
            self.setup_nodes(
                binary=[
                           os.path.join(
                               os.path.dirname(os.path.realpath(__file__)),
                               "../target/release/conflux",
                           )
                       ]
                       * self.num_nodes
            )

    def run_test(self):
        # Start mininode connection
        start_p2p_connection(self.nodes, self.remote, self.local_ip)

        tx_file_path = (
            self.TX_FILE
        )
        f = open(tx_file_path, "rb")

        init_txs = []
        for nonce in range(0, self.num_nodes):
            i = nonce
            addr = self.nodes[i].addr
            init_tx = create_transaction(
                pri_key=ConfluxEthReplayTest.GENESIS_KEY,
                value=10000000000000000, receiver=addr, nonce=nonce)
            init_txs.append(init_tx)

        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=init_txs))

        block_gen_threads = []
        node_id = 0
        for node in self.nodes:
            block_gen_thread = BlockGenThread(
                node_id, node, self.log, random.random(), 1.0 / self.num_nodes
            )
            block_gen_threads.append(block_gen_thread)
            block_gen_thread.start()
            node_id += 1

        time.sleep(self.INITIAL_SLEEP)
        self.log.info("Experiment started")
        start_time = datetime.datetime.now()
        last_log_elapsed_time = 0
        tx_batch_size = 1000
        tx_bytes = 0
        tx_received_slowdown = 0
        tx_count = 0
        expected_elapsed_time = 0

        for txs, count in RlpIter(f, tx_batch_size):
            if tx_count >= ConfluxEthReplayTest.TOTAL_TX_NUMBER:
                break

            elapsed_time = (datetime.datetime.now() - start_time).total_seconds()
            speed_diff = expected_elapsed_time - elapsed_time
            if speed_diff > 0:
                time.sleep(speed_diff)

            # peers_to_send = range(0, self.num_nodes)
            peer_to_send = random.choice(range(0, self.num_nodes))
            # peer_to_send = 0
            peer_to_ask = 0
            txs_rlp = rlp.codec.length_prefix(len(txs), 192) + txs
            self.nodes[peer_to_send].p2p.send_protocol_packet(
                txs_rlp + int_to_bytes(TRANSACTIONS)
            )

            tx_bytes += len(txs)
            expected_elapsed_time = (
                    tx_received_slowdown
                    + 1.0 * tx_bytes / ConfluxEthReplayTest.EXPECTED_TX_SIZE_PER_SEC
            )

            if int(elapsed_time - last_log_elapsed_time) >= 1:
                txpool_status = self.nodes[peer_to_ask].txpool_status()
                txpool_received = txpool_status["received"]
                last_log_elapsed_time = elapsed_time

                self.log.info(
                    "elapsed %ss,\t sent %s/%s(%s%%) txs",
                    elapsed_time,
                    tx_count,
                    ConfluxEthReplayTest.TOTAL_TX_NUMBER,
                    tx_count * 100.0 / ConfluxEthReplayTest.TOTAL_TX_NUMBER,
                )

                final_slow_down = 0

                if txpool_received + 300000 < tx_count:
                    if txpool_received == 0:
                        should_sleep = 1
                    else:
                        should_sleep = (
                                elapsed_time
                                * (tx_count - txpool_received - 290000)
                                / txpool_received
                                + 1
                        )
                    final_slow_down = max(final_slow_down, should_sleep)
                    self.log.warning(
                        "Conflux node %s is slow by %s at receiving txs, slow down by %s.",
                        peer_to_ask,
                        tx_count - txpool_received,
                        should_sleep,
                    )

                txpool_unpacked = txpool_status["unexecuted"]
                unpacked_limit = 300000
                if txpool_unpacked > unpacked_limit:
                    if txpool_received - txpool_unpacked == 0:
                        should_sleep = 1
                    else:
                        should_sleep = (
                                elapsed_time
                                * (txpool_unpacked - unpacked_limit)
                                / (txpool_received - txpool_unpacked)
                                + 1
                        )
                    final_slow_down = max(final_slow_down, should_sleep)
                    self.log.warning(
                        "Conflux node %s has too many unpacked txs %s. sleep %s",
                        peer_to_ask,
                        txpool_unpacked,
                        should_sleep,
                    )
                tx_received_slowdown += final_slow_down

            tx_count += count

        f.close()

        end_time = datetime.datetime.now()
        time_used = (end_time - start_time).total_seconds()
        for block_gen_thread in block_gen_threads:
            block_gen_thread.stop()
        for block_gen_thread in block_gen_threads:
            block_gen_thread.join()
        self.log.info(
            "100%% Ethereum Transactions completely replayed. Time used: %f seconds",
            time_used,
        )
        self.log.info("Transaction per second: %f", tx_count / time_used)

        # time.sleep(2000000)


class BlockGenThread(threading.Thread):
    BLOCK_FREQ = 0.25
    BLOCK_TX_LIMIT = 10000
    BLOCK_SIZE_LIMIT = 800000
    SIMPLE_TX_PER_BLOCK = 0
    # Seems to be 90bytes + artificial 128b
    # Seems to be 90 + 64 bytes.
    # ERC20_TX_PER_BLOCK = 50
    ERC20_TX_PER_BLOCK = 0

    def __init__(self, node_id, node, log, seed, hashpower):
        threading.Thread.__init__(self, daemon=True)
        self.node = node
        self.node_id = node_id
        self.log = log
        self.local_random = random.Random()
        self.local_random.seed(seed)
        self.stopped = False
        self.hashpower_percent = hashpower

    def run(self):
        self.log.info("block gen %s thread started to run", self.node_id)
        # start_time = datetime.datetime.now()
        # pre_generated_blocks = math.ceil(1.0 * ConfluxEthReplayTest.INITIALIZE_TXS / BlockGenThread.BLOCK_TX_LIMIT)
        # for i in range(0, pre_generated_blocks):
        #     if self.stopped:
        #         return
        #     sleep_sec = 1.0 * i * ConfluxEthReplayTest.INITIALIZE_SLEEP / 2 / pre_generated_blocks + 1.0 * i - (
        #             datetime.datetime.now() - start_time).total_seconds()
        #     self.log.info("%s sleep %s at test startup", self.node_id, sleep_sec)
        #     if sleep_sec > 0:
        #         time.sleep(sleep_sec)
        #     if self.node_id == 0:
        #         h = self.node.generateoneblock(BlockGenThread.BLOCK_TX_LIMIT, BlockGenThread.BLOCK_SIZE_LIMIT * 10)
        #         self.log.info("node %s generated block at test start %s", self.node_id, h)
        # for blocks to propogate.

        start_time = datetime.datetime.now()
        total_mining_sec = 0.0
        while not self.stopped:
            try:
                elapsed_sec = (datetime.datetime.now() - start_time).total_seconds()
                sleep_sec = total_mining_sec - elapsed_sec
                self.log.debug(
                    "%s elapsed time %s, total mining time %s sec, actually sleep %s sec",
                    self.node_id,
                    elapsed_sec,
                    total_mining_sec,
                    sleep_sec,
                )
                if sleep_sec > 0:
                    time.sleep(sleep_sec)

                mining = (
                        BlockGenThread.BLOCK_FREQ
                        * numpy.random.exponential()
                        / self.hashpower_percent
                )
                # self.log.info("%s sleep %s sec then generate block", self.node_id, mining)
                total_mining_sec += mining

                # TODO: open the flag
                """ if False:
                    # Use getblockcount to compare with number of generated blocks to compare with expectation,
                    # then set number of generated txs, also report the number of generated txs to help calculation.
                    received_blocks = self.node.getblockcount()
                    expected_generated_blocks = pre_generated_blocks \
                                                + (datetime.datetime.now() - start_time).total_seconds() \
                                                / BlockGenThread.BLOCK_FREQ
                    lag = expected_generated_blocks - received_blocks
                    if lag >= 50:
                        if lag < 100:
                            generate_factor = 1.0 * (100 - lag)
                        else:
                            generate_factor = 0.0
                    else:
                        generate_factor = 1.0"""

                generate_factor = 1.0
                simple_tx_count = math.ceil(
                    BlockGenThread.SIMPLE_TX_PER_BLOCK * generate_factor
                )
                if elapsed_sec < ConfluxEthReplayTest.INITIAL_SLEEP:
                    simple_tx_count = 0
                erc20_tx_count = math.ceil(
                    BlockGenThread.ERC20_TX_PER_BLOCK * generate_factor
                )
                self.node.generateoneblockspecial(
                    BlockGenThread.BLOCK_TX_LIMIT,
                    BlockGenThread.BLOCK_SIZE_LIMIT,
                    simple_tx_count,
                    erc20_tx_count,
                )
                self.log.info(
                    "node %s generated one block with %s extra dummy tx and %s extra erc20 tx",
                    self.node_id,
                    simple_tx_count,
                    erc20_tx_count,
                )
            except Exception as e:
                self.log.warning(
                    "node %s Fails to generate blocks with error msg: %s",
                    self.node_id,
                    e,
                )
                time.sleep(5)
        self.log.info("block gen %s thread is terminated", self.node_id)

    def stop(self):
        self.log.info("Terminating block gen %s thread", self.node_id)
        self.stopped = True


if __name__ == "__main__":
    ConfluxEthReplayTest().main()
