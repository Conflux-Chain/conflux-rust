import random
import threading
import json
import enum

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.blocktools import create_block
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


class Timer(threading.Timer):
    def run(self):
        while not self.finished.wait(self.interval):
            if not self.finished.is_set():
                self.function(*self.args, **self.kwargs)
            else:
                break


class BlockStatus(enum.Enum):
    Valid = 0
    Invalid = 1
    PartialInvalid = 2
    Pending = 3


class ConsensusBlockStatus(object):
    def __init__(self, json_data):
        self.hash = json_data['blockHash']
        self.best_block_hash = json_data['bestBlockHash']
        self.block_status = BlockStatus(json_data['blockStatus'])
        self.past_era_weight = json_data['pastEraWeight']
        self.era_block = json_data['eraBlock']
        self.stable = json_data['stable']
        self.adaptive = json_data['adaptive']


class ConsensusExecutionStatus(object):
    def __init__(self, json_data):
        self.hash = json_data['blockHash']
        self.deferred_state_root = json_data['deferredStateRoot']
        self.deferred_receipt_root = json_data['deferredReceiptRoot']
        self.deferred_logs_bloom_hash = json_data['deferredLogsBloomHash']
        self.state_valid = json_data['stateValid']


class ConsensusSnapshot(object):
    def __init__(self):
        self.block_status_verified = {}
        self.block_status_unverified = {}
        self.exec_status_verified = {}
        self.exec_status_unverified = {}

    def add_block(self, block):
        if block.hash in self.block_status_verified:
            verified_block = self.block_status_verified[block.hash]
            if block.block_status != BlockStatus.Pending:
                assert block.block_status == verified_block.block_status
                assert block.stable == verified_block.stable
                assert block.adaptive == verified_block.adaptive
                assert block.era_block == verified_block.era_block
                assert block.past_era_weight == verified_block.past_era_weight
        elif block.hash in self.block_status_unverified:
            unverified_block = self.block_status_unverified[block.hash]
            if unverified_block.block_status == BlockStatus.Pending:
                self.block_status_unverified[block.hash] = block
            else:
                if block.block_status != BlockStatus.Pending:
                    assert block.block_status == unverified_block.block_status
                    assert block.stable == unverified_block.stable
                    assert block.adaptive == unverified_block.adaptive
                    assert block.era_block == unverified_block.era_block
                    assert block.past_era_weight == unverified_block.past_era_weight
        else:
            self.block_status_unverified[block.hash] = block

    def add_exec(self, exec):
        if exec.hash in self.exec_status_verified:
            verified_exec = self.exec_status_verified[exec.hash]
            assert exec.deferred_state_root == verified_exec.deferred_state_root
            assert exec.deferred_receipt_root == verified_exec.deferred_receipt_root
            assert exec.deferred_logs_bloom_hash == verified_exec.deferred_logs_bloom_hash
            assert exec.state_valid == verified_exec.state_valid
        elif exec.hash in self.exec_status_unverified:
            unverified_exec = self.exec_status_unverified[exec.hash]
            assert exec.deferred_state_root == unverified_exec.deferred_state_root
            assert exec.deferred_receipt_root == unverified_exec.deferred_receipt_root
            assert exec.deferred_logs_bloom_hash == unverified_exec.deferred_logs_bloom_hash
            assert exec.state_valid == unverified_exec.state_valid
        else:
            self.exec_status_unverified[exec.hash] = exec


class Snapshot(object):
    def __init__(self):
        self.consensus = ConsensusSnapshot()
        self.sync_graph = None
        self.network = None

    def update(self, delta):
        """
            incremental evaluation on delta data
        """
        # print("add blockStateVec: {}, blockExecutionStateVec: {}".format(
        #     len(delta['blockStateVec']), len(delta['blockExecutionStateVec'])))
        for block_status in delta['blockStateVec']:
            self.consensus.add_block(ConsensusBlockStatus(block_status))
        for exec_status in delta['blockExecutionStateVec']:
            self.consensus.add_exec(ConsensusExecutionStatus(exec_status))


class ConfluxTracing(ConfluxTestFramework):
    def __init__(self, crash_timeout=10, start_timeout=10, blockgen_timeout=0.25, snapshot_timeout=5.0):
        super().__init__()
        self._lock = threading.Lock()
        self._peer_lock = threading.Lock()
        self._crash_timeout = crash_timeout
        self._start_timeout = start_timeout
        self._blockgen_timeout = blockgen_timeout
        self._snapshot_timeout = snapshot_timeout

        self._snapshots = []
        self._predicates = []
        self._stopped_peers = []

    def _retrieve_alive_peers(self, phase):
        alive_peer_indices = {}
        for (i, node) in enumerate(self.nodes):
            if i not in self._stopped_peers:
                sync_phase = node.current_sync_phase()
                if sync_phase in phase:
                    alive_peer_indices.setdefault(sync_phase, []).append(i)
        return alive_peer_indices

    def _random_start(self):
        if len(self._stopped_peers):
            self._peer_lock.acquire()
            chosen_peer = self._stopped_peers[random.randint(
                0, len(self._stopped_peers) - 1)]
            self._stopped_peers.remove(chosen_peer)
            self.log.info("start {}".format(chosen_peer))
            self.start_node(chosen_peer, phase_to_wait=None)
            self._peer_lock.release()

    def _random_crash(self):
        self._peer_lock.acquire()
        alive_peer_indices = self._retrieve_alive_peers(
            ["NormalSyncPhase", "alive_peer_indices"])
        normal_peers = alive_peer_indices.get('NormalSyncPhase', [])
        catch_up_peers = alive_peer_indices.get('alive_peer_indices', [])
        if len(normal_peers) * 2 < len(self.nodes):
            self._peer_lock.release()
            return
        alive_peer_indices = normal_peers + catch_up_peers
        chosen_peer = alive_peer_indices[random.randint(
            0, len(alive_peer_indices) - 1)]
        self.log.info("stop {}".format(chosen_peer))
        self.stop_node(chosen_peer)
        self._stopped_peers.append(chosen_peer)
        self._peer_lock.release()

    def _generate_block(self):
        """
            random select an alive peer and generate a block
        """
        self._peer_lock.acquire()
        alive_peer_indices = self._retrieve_alive_peers(["NormalSyncPhase"])
        alive_peer_indices = alive_peer_indices.get('NormalSyncPhase', [])
        assert len(alive_peer_indices) * 2 > len(self.nodes)
        chosen_peer = alive_peer_indices[random.randint(
            0, len(alive_peer_indices) - 1)]
        block_hash = RpcClient(self.nodes[chosen_peer]).generate_block(1000)
        self.log.info("%d generate block %s", chosen_peer, block_hash)
        self._peer_lock.release()

    def _retrieve_snapshot(self):
        self._peer_lock.acquire()
        for (snapshot, (i, node)) in zip(self._snapshots, enumerate(self.nodes)):
            # skip stopped nodes
            if i in self._stopped_peers:
                continue
            delta = node.consensus_graph_state()
            snapshot.update(delta)
        self._peer_lock.release()
        self._lock.acquire()
        for predicate in self._predicates:
            predicate(self._snapshots)
        self._lock.release()

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 8
        self.conf_parameters = {
            "log_level": "\"debug\"",
            "generate_tx": "true",
            "generate_tx_period_us": "100000",
            "enable_state_expose": "true"
        }

    def setup_network(self):
        self.log.info("setup nodes ...")
        self.setup_nodes()
        self.log.info("connect peers ...")
        connect_sample_nodes(self.nodes, self.log)
        self.log.info("sync up with blocks among nodes ...")
        sync_blocks(self.nodes)
        self.log.info("start P2P connection ...")
        start_p2p_connection(self.nodes)

    def setup_balance(self):
        client = RpcClient(self.nodes[0])
        for (i, node) in enumerate(self.nodes):
            pub_key = node.key
            addr = node.addr
            self.log.info("%d has addr=%s pubkey=%s",
                          i, encode_hex(addr), pub_key)
            tx = client.new_tx(value=int(
                default_config["TOTAL_COIN"]/self.num_nodes) - 21000, receiver=encode_hex(addr), nonce=i)
            client.send_tx(tx)

    def run_test(self):
        crash_timer = Timer(self._crash_timeout, self._random_crash)
        start_timer = Timer(self._start_timeout, self._random_start)
        blockgen_timer = Timer(self._blockgen_timeout, self._generate_block)
        snapshot_timer = Timer(self._snapshot_timeout, self._retrieve_snapshot)

        self._snapshots = [Snapshot() for _ in self.nodes]
        self.setup_balance()

        crash_timer.start()
        start_timer.start()
        blockgen_timer.start()
        snapshot_timer.start()

        # TODO: we may make it run forever
        time.sleep(200)

        crash_timer.cancel()
        start_timer.cancel()
        blockgen_timer.cancel()
        snapshot_timer.cancel()

        # wait for timer exit
        time.sleep(10)

    def add_predicate(self, predicate):
        assert callable(predicate)
        self._lock.acquire()
        self._predicates.append(predicate)
        self._lock.release()
