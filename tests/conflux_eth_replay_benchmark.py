#!/usr/bin/env python3
from concurrent.futures import ThreadPoolExecutor
import datetime
import math
from http.client import CannotSendRequest
import signal

from conflux.utils import convert_to_nodeid, priv_to_addr, parse_as_int, encode_hex, int_to_hex
from eth_utils import decode_hex, encode_hex as encode_hex_0x
from test_framework.blocktools import  create_transaction
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *
from web3 import Web3
from easysolc import Solc
import rlp
import numpy

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
                    (prefix, type, length, end) = rlp.codec.consume_length_prefix(self.bytes, self.offset)
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
            return (rlpbytes, txs)
        else:
            raise StopIteration()

class TestFinalize():
    def __init__(self, block_gens, confirm_monitor):
        self.block_gens = block_gens
        self.confirm_monitor = confirm_monitor

    def stop(self):
        for block_gen_thread in self.block_gens:
            block_gen_thread.stop()
        self.confirm_monitor.stop()
        for block_gen_thread in self.block_gens:
            block_gen_thread.join()
        self.confirm_monitor.join()

    def signal_handler(self, sig, frame):
        print("Ctrl-C pressed, stop and reset signal handler")
        signal.signal(signal.SIGINT, signal.default_int_handler)
        self.stop()

class ConfluxEthReplayTest(ConfluxTestFramework):
    # For eth + payments.
    #EXPECTED_TX_SIZE_PER_SEC = 100000
    # Eth tx do not have enough concurrency.
    # For eth replay; ~2.5k tps
    EXPECTED_TX_SIZE_PER_SEC = 250000
    # commented out previous ver
    INITIALIZE_TXS = 250000 # 25k for eth genesis and bootstrap
    INITIALIZE_SLEEP = 80 # or 20 for local run
    GENESIS_KEY = decode_hex("9a6d3ba2b0c7514b16a006ee605055d71b9edfad183aeb2d9790e9d4ccced471")

    # FIXME: the base test params has been refactored
    def set_test_params(self):
        self.setup_clean_chain = True

        #""" remote
        ips = []
        try:
            with open("./scripts/ips", 'r') as ip_file:
                for line in ip_file.readlines():
                    ips.append(line[:-1])
        except Exception:
            pass

        self.ips = ips

        self.num_nodes = len(ips)

        """ local run
        self.num_nodes = 1
        """

        self.mining_author = "0x10000000000000000000000000000000000000aa"
        self.conf_parameters = {"log_level": "\"debug\"",
                                # TODO: start mining for eth replay without special transactions?
                                #"start_mining": "true",
                                #"storage_cache_start_size": "1000000",
                                # Do not realloc.
                                "storage_cache_start_size": "20000000",
                                "storage_cache_size": "20000000",
                                "storage_idle_size": "2000000",
                                "storage_node_map_size": "200000000",
                                "ledger_cache_size": "2048",
                                # Do not limit block gas for eth replay
                                "target_block_gas_limit": "100000000000",
                                #"heartbeat_timeout_ms": "10000000000",
                                "tx_pool_size": "800000",
                                "egress_queue_capacity": "2048",
                                "egress_min_throttle": "512",
                                "egress_max_throttle": "1024",}

    # FIXME: we may use the RemoteSimulate base class.
    def setup_network(self):
        #""" remote nodes
        self.remote = True
        self.local_ip = [172, 31, 31, 193]

        binary = ["~/conflux"]

        for ip in self.ips:
            self.add_remote_nodes(1, user="ubuntu", ip=ip, binary=binary)
        for i in range(len(self.nodes)):
            self.log.info("Node "+str(i) + " bind to "+self.nodes[i].ip+":"+self.nodes[i].port)
        self.start_nodes()
        self.log.info("All nodes started, waiting to be connected")
        #"""

        """ local nodes
        self.remote = False
        self.setup_nodes(binary=[os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            #"../target/debug/conflux")]
            "../target/release/conflux")]
            * self.num_nodes)
        #"""

        connect_sample_nodes(self.nodes, self.log, 7, 0, 300)

    def run_test(self):
        # Start mininode connection
        p2p = start_p2p_connection(self.nodes, self.remote)

        #time.sleep(10000)

        confirm_monitor = BlockConfirmationMonitor(self.log, self.nodes)
        confirm_monitor.start()
        block_gen_threads = []
        node_id = 0
        for node in self.nodes:
            block_gen_thread = BlockGenThread(
                self.log, node_id, node, random.random(),
                1.0/self.num_nodes, confirm_monitor)
            block_gen_threads.append(block_gen_thread)
            block_gen_thread.start()
            node_id += 1
        test_finalizer = TestFinalize(block_gen_threads, confirm_monitor)
        signal.signal(signal.SIGINT, test_finalizer.signal_handler)

        TX_FILE_PATH = "../convert_eth_from_0_to_4141811_48945247_txs.rlp"
        f = open(TX_FILE_PATH, "rb")

        start_time = datetime.datetime.now()
        last_log_elapsed_time = 0
        tx_batch_size = 1000
        tx_bytes = 0
        tx_received_slowdown = 0
        # Construct balance distribution transactions and erc20 contract transactions.
        init_txs = []
        solc = Solc()
        erc20_contract = solc.get_contract_instance(
            source=os.path.dirname(os.path.realpath(__file__)) + "/contracts/erc20.sol",
            contract_name="FixedSupplyToken")

        for nonce in range(0, 1):
            genesis_key = ConfluxEthReplayTest.GENESIS_KEY
            genesis_addr = priv_to_addr(ConfluxEthReplayTest.GENESIS_KEY)
            gas_price = 1
            gas = 50000000
            tx_conf = {
                "from":Web3.toChecksumAddress(encode_hex(genesis_addr)),
                "nonce":int_to_hex(nonce), "gas":int_to_hex(gas),
                "gasPrice":int_to_hex(gas_price), "chainId": None}
            raw_create = erc20_contract.constructor().buildTransaction(tx_conf)
            tx_data = decode_hex(raw_create["data"])
            tx_create = create_transaction(pri_key=genesis_key, receiver=b'', nonce=nonce, gas_price=gas_price, data=tx_data, gas=gas, value=0)
            init_txs.append(tx_create)

        erc20_address = Web3.toChecksumAddress(encode_hex(sha3_256(rlp.encode([genesis_addr, nonce]))[-20:]))
        self.log.debug("erc20_address = %s", erc20_address)

        """ Debug only code
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=init_txs))
        time.sleep(10)

        genesis_addr = encode_hex(priv_to_addr(ConfluxEthReplayTest.GENESIS_KEY))
        tx = erc20_contract.functions.balanceOf(Web3.toChecksumAddress(genesis_addr)).buildTransaction({
            "from": Web3.toChecksumAddress(genesis_addr), "gas": int_to_hex(gas), 
            "gasPrice":int_to_hex(gas_price), "to": erc20_address, "chainId": None})
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

        for nonce in range(1, self.num_nodes+1):
            i = nonce - 1
            pub_key = self.nodes[i].key
            addr = self.nodes[i].addr
            init_tx = create_transaction(
                pri_key=ConfluxEthReplayTest.GENESIS_KEY,
                value=10000000000000000, receiver=addr, nonce=nonce)
            init_txs.append(init_tx)

        for nonce in range(self.num_nodes + 1, 2 * self.num_nodes + 1):
            i = nonce - self.num_nodes - 1
            receiver_addr = self.nodes[i].addr

            genesis_key = ConfluxEthReplayTest.GENESIS_KEY
            genesis_addr = priv_to_addr(ConfluxEthReplayTest.GENESIS_KEY)
            value = 10000000000000000

            gas_price = 1
            gas = 100000

            to_address = Web3.toChecksumAddress(encode_hex(receiver_addr))
            tx_data_hex = erc20_contract.functions.transfer(to_address, value).buildTransaction(
                {"gas": int_to_hex(gas), "gasPrice":int_to_hex(gas_price),
                 "to": to_address, "chainId": None})["data"]
            self.log.info("sender %s, receiver %s, value %s, transaction data hex %s", encode_hex_0x(genesis_addr), encode_hex_0x(receiver_addr), hex(value), tx_data_hex)
            tx_data = decode_hex(tx_data_hex)
            tx = create_transaction(pri_key=genesis_key, receiver=decode_hex(erc20_address), value=0, nonce=nonce, gas=gas,
                                    gas_price=gas_price, data=tx_data)
            init_txs.append(tx)

        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=init_txs))

        tx_count = len(init_txs)
        ConfluxEthReplayTest.INITIALIZE_TXS += tx_count

        """ Debug only code
        # Wait for transactions to be inserted into pool.
        time.sleep(1)
        # Deferred exec.
        for _times in range(0, 6):
            self.nodes[0].generateoneblock(2 * self.num_nodes + 1, BlockGenThread.BLOCK_SIZE_LIMIT)
        time.sleep(10)

        caller_addr = encode_hex(self.nodes[0].addr)
        tx = erc20_contract.functions.balanceOf(Web3.toChecksumAddress(caller_addr)).buildTransaction({
            "from": Web3.toChecksumAddress(caller_addr), "gas": int_to_hex(gas),
             "gasPrice":int_to_hex(gas_price), "to": erc20_address, "chainId": None})
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
        tx = erc20_contract.functions.balanceOf(Web3.toChecksumAddress(caller_addr)).buildTransaction({
            "from": Web3.toChecksumAddress(caller_addr), "gas": int_to_hex(gas), 
            "gasPrice":int_to_hex(gas_price), "to": erc20_address, "chainId": None})
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

        for txs, count in RlpIter(f, tx_batch_size):
            # We stop the test after sending 4M txs.
            if tx_count > 4000000:
                self.log.info("Reached 4M txs, stopping")
                break

            txs_rlp = rlp.codec.length_prefix(len(txs), 192) + txs

            sent = False
            while not sent:
                if tx_count < ConfluxEthReplayTest.INITIALIZE_TXS:
                    peers_to_send = [0]
                else:
                    peers_to_send = [0] + random.sample(range(1, self.num_nodes), 1)

                try:
                    for peer_to_send in peers_to_send:
                        self.nodes[peer_to_send].p2p.send_protocol_packet(
                            txs_rlp + int_to_bytes(TRANSACTIONS))
                    sent = True
                except Exception as e:
                    self.log.info("retry sending transactions")
                    # retry

            elapsed_time = (datetime.datetime.now() - start_time).total_seconds()

            if tx_count < ConfluxEthReplayTest.INITIALIZE_TXS:
                expected_elapsed_time = ConfluxEthReplayTest.INITIALIZE_SLEEP / 2.0 \
                    * tx_count / ConfluxEthReplayTest.INITIALIZE_TXS
            else:
                tx_bytes += len(txs)
                expected_elapsed_time = tx_received_slowdown + ConfluxEthReplayTest.INITIALIZE_SLEEP + \
                    1.0 * tx_bytes / ConfluxEthReplayTest.EXPECTED_TX_SIZE_PER_SEC
            speed_diff = expected_elapsed_time - elapsed_time
            if int(elapsed_time - last_log_elapsed_time) >= 1:
                last_log_elapsed_time = elapsed_time
                self.log.info("elapsed time %s, tx_count %s, tx_bytes %s", elapsed_time, tx_count, tx_bytes)

                txpool_status = self.nodes[0].txpool_status()
                # Check if we are sending too fast than txpool can process.
                txpool_received = txpool_status["received"]
                total_executed_txs = self.nodes[0].cfx_getStatus()["totalExecutedTxs"]
                self.log.info(
                    f"elapsed time {elapsed_time} node 0 txpool stats: {repr(txpool_status)}, "
                    f"total_executed_txs: {total_executed_txs}")
                if txpool_received + 50000 < tx_count:
                    # for every one second passed we can add 1 to the expected_elapsed_time
                    tx_received_slowdown += 1
                    self.log.info("Conflux full node is slow by %s at receiving txs, slow down by 1s.", tx_count - txpool_received)
                # To lower the tps to actual rate.
                """ # doesn't work any more because we count at most 1 ready tx per account.
                txpool_ready = txpool_status["ready"]
                if txpool_ready > 60000:
                    should_sleep = elapsed_time * txpool_ready / tx_count
                    tx_received_slowdown = should_sleep
                    self.log.info("Conflux full node has too many ready txs %s. sleep %s", txpool_ready, should_sleep)
                """
                actual_tps = 1.0 * total_executed_txs / elapsed_time
                if actual_tps > 1000:
                    should_sleep = tx_count / actual_tps - elapsed_time
                    if should_sleep > 60:
                        tx_received_slowdown = should_sleep / 2
                        self.log.info(
                            f"Conflux full node has fewer tps {actual_tps}. should sleep {should_sleep}")

            if speed_diff >= 1:
                self.log.info(f"sleep {speed_diff} before sending more txs")
                if speed_diff > 10:
                    speed_diff = 10
                time.sleep(speed_diff)

            tx_count += count

        f.close()

        end_time = datetime.datetime.now()
        time_used = (end_time - start_time).total_seconds()
        test_finalizer.stop()
        self.log.info("Time used: %f seconds", time_used)
        self.log.info("Tx per second: %f", tx_count / time_used)


CONFIRMATION_THRESHOLD = 0.1**6 * 2**256

class BlockConfirmationMonitor(threading.Thread):
    def __init__(self, log, nodes):
        threading.Thread.__init__(self, daemon=True)
        self.log = log
        self.nodes = nodes
        self.block_start_time = {}
        self.block_confirmation_time = {}
        self.unconfirmed_blocks = {}
        self._lock = threading.Lock()

    def add_block(self, block_hash, miner):
        self._lock.acquire()
        self.block_start_time[block_hash] = time.time()
        self.unconfirmed_blocks.setdefault(miner, []).append(block_hash)
        self._lock.release()

    def confirm_block(self, block_hash, miner):
        self._lock.acquire()
        self.block_confirmation_time[block_hash] = time.time() - self.block_start_time[block_hash]
        self.unconfirmed_blocks.get(miner, []).remove(block_hash)
        self._lock.release()

    def get_unconfirmed_blocks(self):
        self._lock.acquire()
        l = []
        for miner, block_list in self.unconfirmed_blocks.items():
            if block_list:
                l.append((miner, block_list[0]))
        self._lock.release()
        return l

    def get_average_latency(self):
        self._lock.acquire()
        confirmation_time = self.block_confirmation_time.values()
        self._lock.release()
        return sum(confirmation_time) / len(confirmation_time)

    def progress(self):
        self._lock.acquire()
        self.log.info(f"generated: {len(self.block_start_time)}, confirmed: {len(self.block_confirmation_time)}")
        self._lock.release()

    def check_if_block_confirmed(self, node_id, block_hash):
        p = random.randint(0, len(self.nodes) - 1)
        risk = self.nodes[p].cfx_getConfirmationRiskByHash(block_hash)
        is_confirmed = risk is not None and int(risk, 16) <= CONFIRMATION_THRESHOLD
        return (node_id, block_hash, is_confirmed)

    def run(self):
        self.running = True
        executor = ThreadPoolExecutor(max_workers=len(self.nodes) / 4)
        while self.running:
            try:
                self.progress()
                futures = []
                for node_id, block in self.get_unconfirmed_blocks():
                    futures.append(executor.submit(self.check_if_block_confirmed, node_id, block))
                for future in futures:
                    node_id, block, is_confirmed = future.result()
                    if is_confirmed:
                        self.confirm_block(block, node_id)
            except Exception as e:
                self.log.info("BlockConfirmationMonitor run into exception %s", e)
            time.sleep(0.5)
        self.log.info(f"BlockConfirmationMonitor stopped, printing average confirmation latency.")
        self.log.info(f"average_confirm_latency: {self.get_average_latency()}")

    def stop(self):
        self.log.info("Stop BlockConfirmationMonitor")
        self.running = False

class BlockGenThread(threading.Thread):
    BLOCK_FREQ=0.25
    # 6k tps max
    BLOCK_TX_LIMIT=int(6000 * BLOCK_FREQ)
    # 1.2MB/s
    BLOCK_SIZE_LIMIT=int(1200000 * BLOCK_FREQ)
    # Seems to be 90bytes + artificial 128b
    #SIMPLE_TX_PER_BLOCK=int(2800 * BLOCK_FREQ)
    SIMPLE_TX_PER_BLOCK=0
    # Seems to be 90 + 64 bytes.
    #ERC20_TX_PER_BLOCK=int(200 * BLOCK_FREQ)
    ERC20_TX_PER_BLOCK=0
    def __init__(self, log, node_id, node, seed, hashpower, confirm_monitor):
        threading.Thread.__init__(self, daemon=True)
        self.node = node
        self.node_id = node_id
        self.log = log
        self.confirm_monitor = confirm_monitor
        self.local_random = random.Random()
        self.local_random.seed(seed)
        self.stopped = False
        self.hashpower_percent = hashpower

    def run(self):
        self.log.info("block gen thread started to run")
        start_time = datetime.datetime.now()
        # The current tx pool won't pack as many transactions from the same sender as before.
        pre_generated_blocks = math.ceil(BlockGenThread.BLOCK_FREQ * ConfluxEthReplayTest.INITIALIZE_TXS / BlockGenThread.BLOCK_TX_LIMIT)
        # so we generate more blocks for ETH genesis accounts.
        pre_generated_blocks = pre_generated_blocks * 10
        for i in range(0, pre_generated_blocks):
            if self.stopped:
                return
            sleep_sec = 1.0 * i * ConfluxEthReplayTest.INITIALIZE_SLEEP / 2 / pre_generated_blocks \
                        - (datetime.datetime.now() - start_time).total_seconds()
            self.log.info("%s sleep %s at test startup", self.node_id, sleep_sec)
            if sleep_sec > 0:
                time.sleep(sleep_sec)
            # prevent from being disconnected by conflux full node.
            self.node.p2p.send_status()
            if self.node_id == 0:
                h = self.node.generateoneblock(BlockGenThread.BLOCK_TX_LIMIT, BlockGenThread.BLOCK_SIZE_LIMIT * 10)
                self.log.info("node %s generated block at test start %s", self.node_id, h)
        # for blocks to propagate.
        time.sleep(ConfluxEthReplayTest.INITIALIZE_SLEEP / 2)

        start_time = datetime.datetime.now()
        total_mining_sec = 0.0
        mining = BlockGenThread.BLOCK_FREQ * numpy.random.exponential() / self.hashpower_percent
        self.log.info("%s sleep %s sec then generate block", self.node_id, mining)
        total_mining_sec += mining
        while not self.stopped:
            try:
                elapsed_sec = (datetime.datetime.now() - start_time).total_seconds()
                sleep_sec = total_mining_sec - elapsed_sec
                self.log.info("%s elapsed time %s, total mining time %s sec, actually sleep %s sec", self.node_id, elapsed_sec, total_mining_sec, sleep_sec)
                if sleep_sec > 0:
                    if sleep_sec > 1:
                        time.sleep(1)
                        continue
                    else:
                        time.sleep(sleep_sec)
                # Now we can generate the block.

                # calculate the time to generate the next block.
                mining = BlockGenThread.BLOCK_FREQ * numpy.random.exponential() / self.hashpower_percent
                self.log.info("%s sleep %s sec then generate next block", self.node_id, mining)
                total_mining_sec += mining

                # TODO: open the flag
                if False:
                    # Use getblockcount to compare with number of generated blocks to compare with expectation, then set number of generated txs, also report the number of generated txs to help calculation.
                    received_blocks = self.node.getblockcount()
                    expected_generated_blocks = pre_generated_blocks + (datetime.datetime.now() - start_time).total_seconds() / BlockGenThread.BLOCK_FREQ
                    lag = expected_generated_blocks - received_blocks
                    if lag >= 50:
                        if lag < 100:
                            generate_factor = 1.0 * (100 - lag)
                        else:
                            generate_factor = 0.0
                    else:
                        generate_factor = 1.0

                generate_factor = 1.0
                simple_tx_count = math.ceil(BlockGenThread.SIMPLE_TX_PER_BLOCK * generate_factor)
                erc20_tx_count = math.ceil(BlockGenThread.ERC20_TX_PER_BLOCK * generate_factor)
                block_hash = self.node.generate_one_block_with_direct_txgen(BlockGenThread.BLOCK_TX_LIMIT, BlockGenThread.BLOCK_SIZE_LIMIT, simple_tx_count, erc20_tx_count)
                self.confirm_monitor.add_block(block_hash, self.node_id)
                # prevent from being disconnected by conflux full node.
                self.node.p2p.send_status()
                self.log.info("%s generated block with %s simple tx and %s erc20 tx", self.node_id, simple_tx_count, erc20_tx_count)
            except Exception as e:
                self.log.info("%s Fails to generate blocks", self.node_id)
                self.log.info("%s %s", self.node_id, e)
                time.sleep(5)

    def stop(self):
        self.log.info("Stop BlockGenThread")
        self.stopped = True


if __name__ == "__main__":
    ConfluxEthReplayTest().main()
