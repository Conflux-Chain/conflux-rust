#!/usr/bin/env python3
import datetime
import math

import numpy
from eth_utils import decode_hex

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
            self.eof = (len(to_append) == 0)
            self.bytes += to_append
            length = len(self.bytes)
        if length > 0:
            old_offset = self.offset
            txs = 0
            for i in range(0, self.batch_size):
                try:
                    (prefix, _type, length, end) = rlp.codec.consume_length_prefix(self.bytes, self.offset)
                    self.offset += len(prefix) + length
                    txs += 1
                except Exception as e:
                    print("error parsing rlp: %s.", e)
                    if self.offset == old_offset:
                        # We assume that a single transaction won't be larger than BUFFER_SIZE
                        raise e
            rlpbytes = self.bytes[old_offset:self.offset]
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
    EXPECTED_TX_SIZE_PER_SEC = 400000
    INITIALIZE_TXS = 200000 + 400 + 400
    INITIALIZE_TPS = 4000
    INITIALIZE_SLEEP = 20
    GENESIS_KEY = decode_hex("9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471")

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
                with open(self.options.remote_ips, 'r') as ip_file:
                    for line in ip_file.readlines():
                        ips.append(line.strip().strip(','))
            except Exception:
                pass

            self.ips = ips
            self.num_nodes = len(ips)
        else:
            self.num_nodes = 1

        self.conf_parameters = {"log_level": "\"warn\"",
                                # "storage_cache_start_size": "1000000",
                                # Do not re-alloc.
                                "storage_cache_start_size": "20000000",
                                "storage_cache_size": "20000000",
                                "storage_idle_size": "2000000",
                                "storage_node_map_size": "200000000",
                                "ledger_cache_size": "3000",
                                "send_tx_period_ms": "1300",
                                "enable_discovery": "false",
                                "egress_queue_capacity": "1024",
                                "egress_min_throttle": "100",
                                "egress_max_throttle": "1000", }
        self.initialize_chain_clean()

    def setup_network(self):
        if self.remote:
            binary_path = ["/home/ubuntu/conflux"]
            for ip in self.ips:
                self.add_remote_nodes(1, user="ubuntu", ip=ip, binary=binary_path, no_pssh=True)
            for i in range(len(self.nodes)):
                self.log.info("Node " + str(i) + " bind to " + self.nodes[i].ip + ":" + self.nodes[i].port)
            self.start_nodes()
            self.log.info("All nodes started, waiting to be connected")
            connect_sample_nodes(nodes=self.nodes, log=self.log, sample=7, latency_min=0, latency_max=300)
        else:
            self.setup_nodes(binary=[os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "../target/release/conflux")]
                                    * self.num_nodes)

    def run_test(self):
        # Start mininode connection
        start_p2p_connection(self.nodes, self.remote, self.local_ip)

        # time.sleep(10000)

        block_gen_threads = []
        node_id = 0
        for node in self.nodes:
            block_gen_thread = BlockGenThread(node_id, node, self.log, random.random(), 1.0 / self.num_nodes)
            block_gen_threads.append(block_gen_thread)
            block_gen_thread.start()
            node_id += 1

        tx_file_path = "/home/ubuntu/convert_eth_from_0_to_4141811_unknown_txs.rlp"
        f = open(tx_file_path, "rb")

        start_time = datetime.datetime.now()
        last_log_elapsed_time = 0
        tx_batch_size = 1000
        tx_bytes = 0
        tx_received_slowdown = 0

        # Construct balance distribution transactions and erc20 contract transactions.
        init_txs = []
        # solc = Solc()
        # erc20_contract = solc.get_contract_instance(source=os.path.dirname(os.path.realpath(__file__)) + "/erc20.sol",
        #                                             contract_name="FixedSupplyToken")

        # nonce = 0
        # genesis_key = ConfluxEthReplayTest.GENESIS_KEY
        # genesis_addr = privtoaddr(ConfluxEthReplayTest.GENESIS_KEY)
        # gas_price = 1
        # gas = 50000000
        # tx_conf = {"from": Web3.toChecksumAddress(encode_hex(genesis_addr)),
        #            "nonce": int_to_hex(nonce),
        #            "gas": int_to_hex(gas),
        #            "gasPrice": int_to_hex(gas_price)}
        # raw_create = erc20_contract.constructor().buildTransaction(tx_conf)
        # tx_data = decode_hex(raw_create["data"])
        # tx_create = create_transaction(pri_key=genesis_key,
        #                                receiver=b'',
        #                                nonce=nonce,
        #                                gas_price=gas_price,
        #                                data=tx_data,
        #                                gas=gas,
        #                                value=0)
        # init_txs.append(tx_create)

        # erc20_address = Web3.toChecksumAddress(encode_hex(sha3_256(rlp.encode([genesis_addr, nonce]))[-20:]))
        # self.log.debug("erc20_address = %s", erc20_address)

        """Debug only code
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=init_txs))
        time.sleep(10)

        genesis_addr = encode_hex(privtoaddr(ConfluxEthReplayTest.GENESIS_KEY))
        tx = erc20_contract.functions.balanceOf(Web3.toChecksumAddress(genesis_addr)).buildTransaction({
            "from": Web3.toChecksumAddress(genesis_addr),
            "gas": int_to_hex(gas),
            "gasPrice":int_to_hex(gas_price),
            "to": erc20_address})
        tx["value"] = int_to_hex(tx['value'])
        tx["hash"] = "0x"+"0"*64
        tx["nonce"] = int_to_hex(1)
        tx["v"] = "0x0"
        tx["r"] = "0x0"
        tx["s"] = "0x0"
        result = self.nodes[0].cfx_call(tx)
        balance = bytes_to_int(decode_hex(result))
        self.log.debug("address=%s, balance=%s", genesis_addr, balance)
        """

        # for nonce in range(1, self.num_nodes + 1):
        #     i = nonce - 1
        #     addr = self.nodes[i].addr
        #     init_tx = create_transaction(
        #         pri_key=ConfluxEthReplayTest.GENESIS_KEY,
        #         value=10000000000000000, receiver=addr, nonce=nonce)
        #     init_txs.append(init_tx)

        # for nonce in range(self.num_nodes + 1, 2 * self.num_nodes + 1):
        #     i = nonce - self.num_nodes - 1
        #     receiver_addr = self.nodes[i].addr
        #
        #     genesis_key = ConfluxEthReplayTest.GENESIS_KEY
        #     genesis_addr = privtoaddr(ConfluxEthReplayTest.GENESIS_KEY)
        #     value = 10000000000000000
        #
        #     gas_price = 1
        #     gas = 100000
        #
        #     to_address = Web3.toChecksumAddress(encode_hex(receiver_addr))
        #     tx_data_hex = erc20_contract.functions.transfer(to_address, value).buildTransaction({
        #         "gas": int_to_hex(gas),
        #         "gasPrice": int_to_hex(gas_price),
        #         "to": to_address})["data"]
        #     self.log.info("sender %s, receiver %s, value %s, transaction data hex %s",
        #                   encode_hex_0x(genesis_addr), encode_hex_0x(receiver_addr), hex(value), tx_data_hex)
        #     tx_data = decode_hex(tx_data_hex)
        #     tx = create_transaction(pri_key=genesis_key, receiver=decode_hex(erc20_address), value=0, nonce=nonce,
        #                             gas=gas, gas_price=gas_price, data=tx_data)
        #     init_txs.append(tx)
        #
        # print(self.nodes)
        # self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=init_txs))

        tx_count = len(init_txs)

        """Debug only code
        # Wait for transactions to be inserted into pool.
        time.sleep(1)
        # Deferred exec.
        for _times in range(0, 6):
            self.nodes[0].generateoneblock(2 * self.num_nodes + 1, BlockGenThread.BLOCK_SIZE_LIMIT)
        time.sleep(10)

        caller_addr = encode_hex(self.nodes[0].addr)
        tx = erc20_contract.functions.balanceOf(Web3.toChecksumAddress(caller_addr)).buildTransaction(
            {"from": Web3.toChecksumAddress(caller_addr),
             "gas": int_to_hex(gas),
             "gasPrice":int_to_hex(gas_price),
             "to": erc20_address})
        tx["value"] = int_to_hex(tx['value'])
        tx["hash"] = "0x"+"0"*64
        tx["nonce"] = int_to_hex(0)
        tx["v"] = "0x0"
        tx["r"] = "0x0"
        tx["s"] = "0x0"
        result = self.nodes[0].cfx_call(tx)
        balance = bytes_to_int(decode_hex(result))
        self.log.debug("address=%s, balance=%s", caller_addr, balance)

        self.nodes[0].generateoneblockspecial(0, BlockGenThread.BLOCK_SIZE_LIMIT, 1, 1)
        # Deferred exec.
        for _times in range(0, 6):
            self.nodes[0].generateoneblock(2 * self.num_nodes + 1, BlockGenThread.BLOCK_SIZE_LIMIT)
        time.sleep(10)

        caller_addr = encode_hex(self.nodes[0].addr)
        tx = erc20_contract.functions.balanceOf(Web3.toChecksumAddress(caller_addr)).buildTransaction(
            {"from": Web3.toChecksumAddress(caller_addr),
             "gas": int_to_hex(gas),
             "gasPrice":int_to_hex(gas_price),
             "to": erc20_address})
        tx["value"] = int_to_hex(tx['value'])
        tx["hash"] = "0x"+"0"*64
        tx["nonce"] = int_to_hex(2)
        tx["v"] = "0x0"
        tx["r"] = "0x0"
        tx["s"] = "0x0"
        result = self.nodes[0].cfx_call(tx)
        balance = bytes_to_int(decode_hex(result))
        self.log.debug("address=%s, balance=%s", caller_addr, balance)

        time.sleep(2000)
        """

        total = 4000000
        expected_elapsed_time = 0

        for txs, count in RlpIter(f, tx_batch_size):
            if tx_count > total:
                break

            elapsed_time = (datetime.datetime.now() - start_time).total_seconds()
            speed_diff = expected_elapsed_time - elapsed_time
            if speed_diff > 0:
                time.sleep(speed_diff)

            peers_to_send = range(0, self.num_nodes)
            txs_rlp = rlp.codec.length_prefix(len(txs), 192) + txs
            for peer_to_send in peers_to_send:
                self.nodes[peer_to_send].p2p.send_protocol_packet(int_to_bytes(TRANSACTIONS) + txs_rlp)

            tx_bytes += len(txs)
            expected_elapsed_time = tx_received_slowdown + 1.0 * tx_bytes / ConfluxEthReplayTest.EXPECTED_TX_SIZE_PER_SEC

            if int(elapsed_time - last_log_elapsed_time) >= 1:
                txpool_status = self.nodes[0].txpool_status()
                txpool_received = txpool_status["received"]
                last_log_elapsed_time = elapsed_time

                self.log.info("elapsed %ss,\t sent %s/%s(%s%%) txs", elapsed_time, tx_count, total,
                              tx_count * 100.0 / total)

                final_slow_down = 0

                if txpool_received + 50000 < tx_count:
                    if txpool_received == 0:
                        should_sleep = 1
                    else:
                        should_sleep = elapsed_time * (tx_count - txpool_received) / txpool_received + 1
                    final_slow_down = max(final_slow_down, should_sleep)
                    self.log.info("Conflux full node is slow by %s at receiving txs, slow down by %s.",
                                  tx_count - txpool_received, should_sleep)

                txpool_unpacked = txpool_status["unpacked"]
                unpacked_limit = 300000
                if txpool_unpacked > unpacked_limit:
                    if txpool_received - txpool_unpacked == 0:
                        should_sleep = 1
                    else:
                        should_sleep = elapsed_time * (txpool_unpacked - unpacked_limit) / (
                                    txpool_received - txpool_unpacked) + 1
                    final_slow_down = max(final_slow_down, should_sleep)
                    self.log.info("Conflux full node has too many unpacked txs %s. sleep %s", txpool_unpacked,
                                  should_sleep)
                tx_received_slowdown += final_slow_down

            tx_count += count

        f.close()

        end_time = datetime.datetime.now()
        time_used = (end_time - start_time).total_seconds()
        for block_gen_thread in block_gen_threads:
            block_gen_thread.stop()
            block_gen_thread.join()
        self.log.info("100%% Ethereum Transactions completely replayed. Time used: %f seconds", time_used)
        self.log.info("Transaction per second: %f", tx_count / time_used)

        time.sleep(2000000000)


class BlockGenThread(threading.Thread):
    BLOCK_FREQ = 5
    BLOCK_TX_LIMIT = 60000
    BLOCK_SIZE_LIMIT = 6000000
    # Seems to be 90bytes + artificial 128b
    # SIMPLE_TX_PER_BLOCK = 700
    SIMPLE_TX_PER_BLOCK = 0
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
        self.log.info("block gen thread started to run")
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
        # time.sleep(ConfluxEthReplayTest.INITIALIZE_SLEEP / 2)

        start_time = datetime.datetime.now()
        total_mining_sec = 0.0
        while not self.stopped:
            try:
                elapsed_sec = (datetime.datetime.now() - start_time).total_seconds()
                sleep_sec = total_mining_sec - elapsed_sec
                self.log.info("%s elapsed time %s, total mining time %s sec, actually sleep %s sec",
                              self.node_id, elapsed_sec, total_mining_sec, sleep_sec)
                if sleep_sec > 0:
                    time.sleep(sleep_sec)

                mining = BlockGenThread.BLOCK_FREQ * numpy.random.exponential() / self.hashpower_percent
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
                simple_tx_count = math.ceil(BlockGenThread.SIMPLE_TX_PER_BLOCK * generate_factor)
                erc20_tx_count = math.ceil(BlockGenThread.ERC20_TX_PER_BLOCK * generate_factor)
                self.node.generateoneblockspecial(BlockGenThread.BLOCK_TX_LIMIT,
                                                  BlockGenThread.BLOCK_SIZE_LIMIT, simple_tx_count, erc20_tx_count)
                self.log.info("%s generated block with %s simple tx and %s erc20 tx",
                              self.node_id, simple_tx_count, erc20_tx_count)
            except Exception as e:
                self.log.info("%s Fails to generate blocks", self.node_id)
                self.log.info("%s %s", self.node_id, e)
                time.sleep(5)

    def stop(self):
        self.stopped = True


if __name__ == "__main__":
    ConfluxEthReplayTest().main()
