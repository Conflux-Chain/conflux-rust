#!/usr/bin/env python3
import random
import threading
import json
import enum
import copy
import argparse
import eth_utils
import rlp
import sys
import os
import time

sys.path.insert(1, os.path.dirname(sys.path[0]))

from conflux.rpc import RpcClient
from test_framework.util import *
from test_framework.mininode import *
from test_framework.test_framework import ConfluxTestFramework


DEFAULT_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000'
NUM_TX_PER_BLOCK = 10
CRASH_EXIT_CODE = 100
CRASH_EXIT_PROBABILITY = 0.01


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


class EventBase(object):
    def __init__(self):
        pass

    def execute(self, node):
        raise NotImplementedError()

    def name(self):
        raise NotImplementedError()

    def to_json(self):
        raise NotImplementedError()


class StopEvent(EventBase):
    def __init__(self):
        super().__init__()
        self._name = 'stop'

    def execute(self, node):
        node.stop_node()

    def name(self):
        return self._name

    def to_json(self):
        return {'name': self.name()}


class StartEvent(EventBase):
    def __init__(self):
        super().__init__()
        self._name = 'start'

    def execute(self, node):
        node.start()
        node.wait_for_rpc_connection()
        node.wait_for_nodeid()
        node.wait_for_recovery(
            ["NormalSyncPhase", "CatchUpSyncBlockPhase"], wait_time=100000)

    def name(self):
        return self._name

    def to_json(self):
        return {'name': self.name()}


class NewBlockEvent(EventBase):
    def __init__(self, hash, parent, referees, nonce, timestamp, adaptive, txs=None):
        super().__init__()
        self._name = 'new_block'
        self._hash = hash
        self._parent = parent
        self._referees = referees
        self._nonce = nonce
        self._txs = txs
        self._timestamp = timestamp
        self._adaptive = adaptive

    def execute(self, node):
        assert self._txs is not None
        block_hash = node.test_generate_block_with_nonce_and_timestamp(
            self._parent,
            self._referees,
            self._txs,
            self._nonce,
            self._timestamp,
            self._adaptive)
        assert block_hash == self._hash

    def name(self):
        return self._name

    def to_json(self):
        return {
            'name': self.name(),
            'hash': self._hash,
            'parent': self._parent,
            'referees': self._referees,
            'nonce': self._nonce,
            'timestamp': self._timestamp,
            'adaptive': self._adaptive,
        }


class ConsensusBlockStatus(object):
    def __init__(self, json_data):
        self.hash = json_data['blockHash']
        self.best_block_hash = json_data['bestBlockHash']
        self.block_status = BlockStatus(json_data['blockStatus'])
        self.era_block_hash = json_data['eraBlockHash']
        self.adaptive = json_data['adaptive']

    def __eq__(self, other):
        if self.block_status == BlockStatus.Pending or \
                other.block_status == BlockStatus.Pending:
            return True
        if self.era_block_hash != DEFAULT_HASH and \
                other.era_block_hash != DEFAULT_HASH and \
                self.era_block_hash != other.era_block_hash:
            return False
        return self.hash == other.hash and \
            self.block_status == other.block_status and \
            self.adaptive == other.adaptive

    def __str__(self):
        return "ConsensusBlockStatus(\
                hash={}, \
                best_block_hash={}, \
                block_status={}, \
                era_block={}, \
                adaptive={})".format(
            self.hash,
            self.best_block_hash,
            self.block_status,
            self.era_block,
            self.adaptive)


class ConsensusExecutionStatus(object):
    def __init__(self, json_data):
        self.hash = json_data['blockHash']
        self.deferred_state_root = json_data['deferredStateRoot']
        self.deferred_receipt_root = json_data['deferredReceiptRoot']
        self.deferred_logs_bloom_hash = json_data['deferredLogsBloomHash']

    def __eq__(self, other):
        return self.hash == other.hash and \
            self.deferred_state_root == other.deferred_state_root and \
            self.deferred_receipt_root == other.deferred_receipt_root and \
            self.deferred_logs_bloom_hash == other.deferred_logs_bloom_hash

    def __str__(self):
        return "ConsensusExecutionStatus(hash={}, deferred_state_root={}, deferred_receipt_root={}, deferred_logs_bloom_hash={})".format(
            self.hash,
            self.deferred_state_root,
            self.deferred_receipt_root,
            self.deferred_logs_bloom_hash)


class ConsensusSnapshot(object):
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.block_status_verified = {}
        self.block_status_unverified = {}
        self.exec_status_verified = {}
        self.exec_status_unverified = {}

    def add_block(self, block):
        if block.hash in self.block_status_verified:
            verified_block = self.block_status_verified[block.hash]
            if block.block_status != BlockStatus.Pending:
                assert block.block_status == verified_block.block_status, "peer[{}] block[{}] status[{}], expect [{}]".format(
                    self.peer_id, block.hash, block.block_status, verified_block.block_status)
                assert block.adaptive == verified_block.adaptive, "peer[{}] block[{}] adaptive[{}], expect [{}]".format(
                    self.peer_id, block.hash, block.adaptive, verified_block.adaptive)
                assert block.era_block_hash == verified_block.era_block_hash or \
                    block.era_block_hash == DEFAULT_HASH, "peer[{}] block[{}] era_block_hash[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.era_block_hash, verified_block.era_block_hash)
        elif block.hash in self.block_status_unverified:
            unverified_block = self.block_status_unverified[block.hash]
            if unverified_block.block_status == BlockStatus.Pending:
                self.block_status_unverified[block.hash] = block
            else:
                if block.block_status != BlockStatus.Pending:
                    assert block.block_status == unverified_block.block_status, "peer[{}] block[{}] status[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.block_status, unverified_block.block_status)
                    assert block.adaptive == unverified_block.adaptive, "peer[{}] block[{}] adaptive[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.adaptive, unverified_block.adaptive)
                    assert block.era_block_hash == unverified_block.era_block_hash or \
                        block.era_block_hash == DEFAULT_HASH or \
                        unverified_block.era_block_hash == DEFAULT_HASH, "peer[{}] block[{}] era_block_hash[{}], expect [{}]".format(
                            self.peer_id, block.hash, block.era_block_hash, unverified_block.era_block_hash)
        else:
            self.block_status_unverified[block.hash] = block

    def add_exec(self, exec):
        if exec.hash in self.exec_status_verified:
            verified_exec = self.exec_status_verified[exec.hash]
            assert exec.deferred_state_root == verified_exec.deferred_state_root, "peer[{}] block[{}] deferred_state_root[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_state_root, verified_exec.deferred_state_root)
            assert exec.deferred_receipt_root == verified_exec.deferred_receipt_root, "peer[{}] block[{}] deferred_receipt_root[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_receipt_root, verified_exec.deferred_receipt_root)
            assert exec.deferred_logs_bloom_hash == verified_exec.deferred_logs_bloom_hash, "peer[{}] block[{}] deferred_logs_bloom_hash[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_logs_bloom_hash, verified_exec.deferred_logs_bloom_hash)
        elif exec.hash in self.exec_status_unverified:
            unverified_exec = self.exec_status_unverified[exec.hash]
            assert exec.deferred_state_root == unverified_exec.deferred_state_root, "peer[{}] block[{}] deferred_state_root[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_state_root, unverified_exec.deferred_state_root)
            assert exec.deferred_receipt_root == unverified_exec.deferred_receipt_root, "peer[{}] block[{}] deferred_receipt_root[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_receipt_root, unverified_exec.deferred_receipt_root)
            assert exec.deferred_logs_bloom_hash == unverified_exec.deferred_logs_bloom_hash, "peer[{}] block[{}] deferred_logs_bloom_hash[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_logs_bloom_hash, unverified_exec.deferred_logs_bloom_hash)
        else:
            self.exec_status_unverified[exec.hash] = exec


class BFTCommit(object):
    def __init__(self, json_data):
        self.epoch = json_data['epoch']
        self.commit = json_data['commit']
        self.round = json_data['round']
        self.parent = json_data['parent']
        self.timestamp = json_data['timestamp']
        self.received_timestamp = time.time()

    def __eq__(self, other):
        return self.epoch == other.epoch and \
            self.commit == other.commit and \
            self.round == other.round and \
            self.parent == other.parent and \
            self.timestamp == other.timestamp

    def __str__(self):
        return "BFTCommit(epoch={}, commit={}, round={}, parent={}, timestamp={})".format(
            self.epoch,
            self.commit,
            self.round,
            self.parent,
            self.timestamp)


class BFTSnashot(object):
    def __init__(self, peer_id):
        self.peer_id = peer_id
        self.round_to_commit = dict()
        self.last_commited = None
        self.round_verified = set()
        self.round_unverified = set()

    def add_event(self, json_data):
        bft_commit = BFTCommit(json_data)
        self.last_commited = bft_commit
        if bft_commit.round in self.round_to_commit:
            assert bft_commit == self.round_to_commit[bft_commit.round], "peer[{}] round=[{}] expected[{}] found[{}]".format(
                self.peer_id, bft_commit.round, str(self.round_to_commit[bft_commit.round]), str(bft_commit))
        self.round_to_commit[bft_commit.round] = bft_commit
        if bft_commit.round not in self.round_verified and bft_commit.round not in self.round_unverified:
            self.round_unverified.add(bft_commit.round)


class Snapshot(object):
    def __init__(self, peer_id, genesis):
        self.genesis = genesis
        self.peer_id = peer_id
        self.consensus = ConsensusSnapshot(peer_id)
        self.bft = BFTSnashot(peer_id)
        self.sync_graph = None
        self.network = None
        self.event_list = []

    def update(self, delta):
        """
            incremental evaluation on delta data
        """
        for block_status in delta['blockStateVec']:
            self.consensus.add_block(ConsensusBlockStatus(block_status))
        for exec_status in delta['blockExecutionStateVec']:
            self.consensus.add_exec(ConsensusExecutionStatus(exec_status))

    def stop(self):
        self.event_list.append(StopEvent())

    def start(self):
        self.bft.last_commited = None
        self.event_list.append(StartEvent())

    def new_commits(self, commits):
        for commit in commits:
            self.bft.add_event(commit)

    def new_blocks(self, blocks):
        for block in blocks:
            self.event_list.append(NewBlockEvent(
                block['blockHash'],
                block['parent'],
                block['referees'],
                block['nonce'],
                block['timestamp'],
                block['adaptive']))

    def to_json(self):
        return {
            'genesis': self.genesis,
            'events': [e.to_json() for e in self.event_list]
        }


class Predicate(object):
    def __call__(self, snapshots, stopped_peers):
        raise NotImplementedError()


class TreeGraphTracing(ConfluxTestFramework):
    def __init__(
            self,
            nodes=11,
            crash_timeout=10,
            start_timeout=10,
            blockgen_timeout=0.25,
            snapshot_timeout=5.0,
            db_crash_timeout=10,
            replay=False,
            snapshot_file=None,
            txs_file=None):
        super().__init__()
        self._lock = threading.Lock()
        self._peer_lock = threading.Lock()
        self._crash_timeout = crash_timeout
        self._start_timeout = start_timeout
        self._blockgen_timeout = blockgen_timeout
        self._snapshot_timeout = snapshot_timeout
        self._db_crash_timeout = db_crash_timeout
        self.num_nodes = nodes
        self._replay = replay
        self._snapshot_file = snapshot_file

        self._snapshots = []
        self._predicates = []
        self._stopped_peers = []
        self._peer_nonce = []
        if txs_file is None:
            self._block_txs = {}
        else:
            self._block_txs = json.load(open(txs_file, 'r'))

    def _retrieve_alive_peers(self, phase):
        alive_peer_indices = {}
        for (i, node) in enumerate(self.nodes):
            if i not in self._stopped_peers:
                sync_phase = node.current_sync_phase()
                if sync_phase in phase:
                    alive_peer_indices.setdefault(sync_phase, []).append(i)
        return alive_peer_indices

    def _random_start(self):
        try:
            if len(self._stopped_peers):
                with self._peer_lock:
                    chosen_peer = self._stopped_peers[random.randint(
                        0, len(self._stopped_peers) - 1)]
                    self.log.info("starting {}".format(chosen_peer))
                    self.start_node(chosen_peer, phase_to_wait=None)
                    self._snapshots[chosen_peer].start()
                    self.log.info("started {}".format(chosen_peer))
                    self._stopped_peers.remove(chosen_peer)
        except Exception as e:
            self.log.info('got exception[{}] during start'.format(repr(e)))
            self.persist_snapshot()
            raise e

    def _random_crash(self):
        try:
            with self._peer_lock:
                alive_peer_indices = self._retrieve_alive_peers(
                    ["NormalSyncPhase", "CatchUpSyncBlockPhase"])
                normal_peers = alive_peer_indices.get('NormalSyncPhase', [])
                catch_up_peers = alive_peer_indices.get(
                    'CatchUpSyncBlockPhase', [])
                if len(self._stopped_peers):
                    return
                if (len(normal_peers) - 1) * 2 <= len(self.nodes):
                    return
                alive_peer_indices = normal_peers + catch_up_peers
                # We need peer[0] to run forever as a reference
                chosen_peer = alive_peer_indices[random.randint(
                    0, len(alive_peer_indices) - 1)]
                if self._snapshots[chosen_peer].bft.last_commited is None:
                    return
                self.log.info("stopping {}".format(chosen_peer))
                # retrieve new ready blocks before stopping it
                new_blocks = self.nodes[chosen_peer].sync_graph_state()
                self._snapshots[chosen_peer].new_blocks(
                    new_blocks['readyBlockVec'])
                self.nodes[chosen_peer].save_node_db()
                self.stop_node(chosen_peer, kill=True)
                self._stopped_peers.append(chosen_peer)
                self._snapshots[chosen_peer].stop()
                self.log.info("stopped {}".format(chosen_peer))
        except Exception as e:
            self.log.info('got exception[{}] during crash'.format(repr(e)))
            self.persist_snapshot()
            raise e

    def _enable_db_crash(self):
        try:
            with self._peer_lock:
                alive_peer_indices = self._retrieve_alive_peers(
                    ["NormalSyncPhase", "CatchUpSyncBlockPhase"])
                normal_peers = alive_peer_indices.get('NormalSyncPhase', [])
                catch_up_peers = alive_peer_indices.get(
                    'CatchUpSyncBlockPhase', [])
                alive_peer_indices = normal_peers + catch_up_peers
                if len(alive_peer_indices) <= 3:
                    return
                # We need peer[0] to run forever as a reference
                chosen_peer = alive_peer_indices[random.randint(
                    1, len(alive_peer_indices) - 1)]
                self.log.info("enable db crash {}".format(chosen_peer))
                self.nodes[chosen_peer].save_node_db()
                self.nodes[chosen_peer].set_db_crash(
                    CRASH_EXIT_PROBABILITY, CRASH_EXIT_CODE)
        except Exception as e:
            self.log.info('got exception[{}] during db crash'.format(repr(e)))
            self.persist_snapshot()
            raise e

    def _generate_txs(self, peer, num):
        client = RpcClient(self.nodes[peer])
        txs = []
        for _ in range(num):
            addr = client.rand_addr()
            tx_gas = client.DEFAULT_TX_GAS
            nonce = self._peer_nonce[peer]
            self._peer_nonce[peer] = nonce + 1
            tx = client.new_tx(receiver=addr, nonce=nonce,
                               value=0, gas=tx_gas, data=b'')
            txs.append(tx)
        return txs

    def _generate_block(self):
        """
            random select an alive peer and generate a block
        """
        try:
            with self._peer_lock:
                alive_peer_indices = self._retrieve_alive_peers(
                    ["NormalSyncPhase"])
                alive_peer_indices = alive_peer_indices.get(
                    'NormalSyncPhase', [])
                chosen_peer = alive_peer_indices[random.randint(
                    0, len(alive_peer_indices) - 1)]
                txs = self._generate_txs(chosen_peer, NUM_TX_PER_BLOCK)
                block_hash = RpcClient(self.nodes[chosen_peer]).generate_block(NUM_TX_PER_BLOCK)
                self.log.info("peer[{}] generate block[{}] and [{}] txs".format(
                    chosen_peer,
                    block_hash,
                    len(txs)))
        except Exception as e:
            self.log.info('got exception[{}]'.format(repr(e)))
            self.persist_snapshot()
            raise e

    def _retrieve_snapshot(self):
        try:
            with self._peer_lock:
                for (snapshot, (i, node)) in zip(self._snapshots, enumerate(self.nodes)):
                    # skip stopped nodes
                    if i in self._stopped_peers:
                        continue
                    delta = node.consensus_graph_state()
                    new_blocks = node.sync_graph_state()
                    bft_commits = node.bft_state()
                    self.log.info("peer[{}] bftEvents=[{}]".format(
                        i,
                        json.dumps(bft_commits)
                    ))
                    snapshot.update(delta)
                    snapshot.new_blocks(new_blocks['readyBlockVec'])
                    snapshot.new_commits(bft_commits['bftEvents'])
            with self._lock:
                for predicate in self._predicates:
                    predicate(self._snapshots, self._stopped_peers)
        except Exception as e:
            self.log.info('got exception[{}] during verify'.format(repr(e)))
            self.persist_snapshot()
            raise e

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 11
        self.conf_parameters = {
            "is_consortium": "true",
            "log_level": "\"debug\"",
            "generate_tx": "true",
            "generate_tx_period_us": "100000",
            "enable_state_expose": "true",
            "era_epoch_count": 100,
            "dev_snapshot_epoch_count": 50,
            "blocks_request_timeout_ms": 8000,
            "headers_request_timeout_ms": 4000,
            "heartbeat_period_interval_ms": 4000
        }

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, auto_recovery=True, is_consortium=True)
        for i in range(0, self.num_nodes):
            self.start_node(i, extra_args=["--tg_archive"], phase_to_wait=None)

    def setup_network(self):
        self.log.info("setup nodes ...")
        self.setup_nodes()
        self.log.info("connect peers ...")
        if len(self.nodes) > 1:
            connect_sample_nodes(self.nodes, self.log, sample=self.num_nodes-1)
        # self.log.info("sync up with blocks among nodes ...")
        # sync_blocks(self.nodes)
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
                default_config["TOTAL_COIN"] / self.num_nodes) - 21000, receiver=encode_hex(addr), nonce=i)
            client.send_tx(tx)

    def persist_snapshot(self):
        return
        self.log.info("saving txs to txs.json")
        with open('txs.json', 'w') as fp:
            fp.write(json.dumps(self._block_txs))
        self.log.info("txs saved to txs.json")
        for (index, snapshot) in enumerate(self._snapshots):
            self.log.info(
                'saving snapshot {} to snapshot_{}.json'.format(index, index))
            with open('snapshot_{}.json'.format(index), 'w') as fp:
                fp.write(json.dumps(snapshot.to_json()))
            self.log.info(
                'snapshot {} saved to snapshot_{}.json'.format(index, index))

    def run_test(self):
        if self._replay:
            self.replay(self._snapshot_file)
            return
        genesis_hash = self.nodes[0].best_block_hash()
        crash_timer = Timer(self._crash_timeout, self._random_crash)
        start_timer = Timer(self._start_timeout, self._random_start)
        blockgen_timer = Timer(self._blockgen_timeout, self._generate_block)
        snapshot_timer = Timer(self._snapshot_timeout, self._retrieve_snapshot)
        # db_crash_timer = Timer(self._db_crash_timeout, self._enable_db_crash)

        self._snapshots = [Snapshot(i, genesis_hash)
                           for i in range(len(self.nodes))]
        self._peer_nonce = [0] * len(self.nodes)
        self.setup_balance()

        crash_timer.start()
        start_timer.start()
        blockgen_timer.start()
        snapshot_timer.start()
        # db_crash_timer.start()

        # TODO: we may make it run forever
        time.sleep(200000)

        # crash_timer.cancel()
        start_timer.cancel()
        blockgen_timer.cancel()
        snapshot_timer.cancel()
        # db_crash_timer.cancel()

        # wait for timer exit
        time.sleep(20)
        self.persist_snapshot()

    def add_predicate(self, predicate):
        assert isinstance(predicate, Predicate)
        with self._lock:
            self._predicates.append(predicate)

    def add_options(self, parser):
        subparsers = parser.add_subparsers(dest='cmd')
        run_parser = subparsers.add_parser('run')
        run_parser.add_argument(
            '-n',
            '--nodes',
            dest='nodes',
            type=int,
            default=11,
            help='number of nodes to run')
        run_parser.add_argument(
            '-ct',
            '--crash-timeout',
            dest='crash_timeout',
            type=float,
            default=50,
            help='random crash interval')
        run_parser.add_argument(
            '-st',
            '--start-timeout',
            dest='start_timeout',
            type=float,
            default=75,
            help='random start interval')
        run_parser.add_argument(
            '-bt',
            '--blockgen-timeout',
            dest='blockgen_timeout',
            type=float,
            default=0.25,
            help='generate block interval')
        run_parser.add_argument(
            '-snt',
            '--snapshot-timeout',
            dest='snapshot_timeout',
            type=float,
            default=2,
            help='snapshot retrieve interval')

        replay_parser = subparsers.add_parser('replay')
        replay_parser.add_argument(
            '-snapshot_file',
            '--snapshot_file',
            dest='snapshot_file',
            required=True,
            help="path of snapshot")
        replay_parser.add_argument(
            '-txs_file',
            '--txs_file',
            dest='txs_file',
            required=True,
            help="path of txs file")


class ExecutionStatusPredicate(Predicate):
    def __init__(self):
        super().__init__()

    def verify_blocks(self, blocks):
        for i in range(1, len(blocks)):
            assert blocks[i] == blocks[0], "check exec status mismatch for block[{}], expected[{}], but [{}] found".format(blocks[i].hash, str(blocks[0]), str(blocks[i]))

    def verify_snapshots(self, snapshots, hashes):
        for h in hashes:
            blocks = [snapshot.consensus.exec_status_unverified[h]
                      for snapshot in snapshots]
            self.verify_blocks(blocks)
            for (snapshot, block) in zip(snapshots, blocks):
                snapshot.consensus.exec_status_verified[h] = block
                del snapshot.consensus.exec_status_unverified[h]

    def __call__(self, snapshots, stopped_peers):
        verified = {}
        for snapshot in snapshots:
            for (k, v) in snapshot.consensus.exec_status_verified.items():
                if k in verified:
                    assert verified[k] == v
                else:
                    verified[k] = v
        verified_hashes = set(verified.keys())
        verifiable_hashes = None
        verifiable_hashes_with_stopped = None
        alive_snapshots = []
        for (i, snapshot) in enumerate(snapshots):
            unverified_hashes = set(
                snapshot.consensus.exec_status_unverified.keys())
            for h in unverified_hashes.intersection(verified_hashes):
                assert verified[h] == snapshot.consensus.exec_status_unverified[h]
                snapshot.consensus.exec_status_verified[h] = verified[h]
                del snapshot.consensus.exec_status_unverified[h]
            if verifiable_hashes_with_stopped is None:
                verifiable_hashes_with_stopped = copy.deepcopy(
                    unverified_hashes)
            else:
                verifiable_hashes_with_stopped &= unverified_hashes
            if i not in stopped_peers:
                if verifiable_hashes is None:
                    verifiable_hashes = copy.deepcopy(unverified_hashes)
                else:
                    verifiable_hashes &= unverified_hashes
                alive_snapshots.append(snapshot)

        self.verify_snapshots(snapshots, verifiable_hashes_with_stopped)
        verifiable_hashes -= verifiable_hashes_with_stopped
        self.verify_snapshots(alive_snapshots, verifiable_hashes)


class BFTLivenessPredicate(Predicate):
    def __init__(self, timeout):
        super().__init__()
        self.timeout = timeout

    def __call__(self, snapshots, stopped_peers):
        for (i, snapshot) in enumerate(snapshots):
            if i in stopped_peers or snapshot.bft.last_commited is None:
                continue
            now = time.time()
            if now - snapshot.bft.last_commited.received_timestamp > self.timeout:
                assert False, "peer[{}] bft commit timeout".format(
                    snapshot.peer_id)


class BFTCommitPredicatePredicate(Predicate):
    def __init__(self):
        super().__init__()

    def verify_commits(self, round, commits):
        for i in range(1, len(commits)):
            assert commits[0] == commits[i], 'round[{}] mismatch'.format(round)

    def verify_snapshots(self, snapshots, rounds):
        for round in rounds:
            commits = [snapshot.bft.round_to_commit[round]
                       for snapshot in snapshots]
            self.verify_commits(round, commits)
            for snapshot in snapshots:
                snapshot.bft.round_unverified.remove(round)
                snapshot.bft.round_verified.add(round)

    def __call__(self, snapshots, stopped_peers):
        verified = {}
        for (i, snapshot) in enumerate(snapshots):
            for round in snapshot.bft.round_verified:
                if round in verified:
                    assert verified[round] == snapshot.bft.round_to_commit[round], "mismatch verified round[{}]".format(
                        round)
                else:
                    verified[round] = snapshot.bft.round_to_commit[round]
        round_verified = set(verified.keys())
        round_verifiable = None
        round_verifiable_with_stopped = None
        alive_snapshots = []
        for (i, snapshot) in enumerate(snapshots):
            round_unverified = snapshot.bft.round_unverified.intersection(
                round_verified)
            for round in round_unverified:
                assert snapshot.bft.round_to_commit[round] == verified[round]
                snapshot.bft.round_verified.add(round)
                snapshot.bft.round_unverified.remove(round)
            if round_verifiable_with_stopped is None:
                round_verifiable_with_stopped = copy.deepcopy(
                    snapshot.bft.round_unverified)
            else:
                round_verifiable_with_stopped &= snapshot.bft.round_unverified
            if i not in stopped_peers:
                alive_snapshots.append(snapshot)
                if round_verifiable is None:
                    round_verifiable = copy.deepcopy(
                        snapshot.bft.round_unverified)
                else:
                    round_verifiable &= snapshot.bft.round_unverified
        self.verify_snapshots(snapshots, round_verifiable_with_stopped)
        round_verifiable -= round_verifiable_with_stopped
        self.verify_snapshots(alive_snapshots, round_verifiable)


def parse_args():
    parser = argparse.ArgumentParser()
    TreeGraphTracing().add_options(parser)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.cmd == 'run':
        conflux_tracing = TreeGraphTracing(
            nodes=args.nodes,
            crash_timeout=args.crash_timeout,
            start_timeout=args.start_timeout,
            blockgen_timeout=args.blockgen_timeout,
            snapshot_timeout=args.snapshot_timeout)
        conflux_tracing.add_predicate(ExecutionStatusPredicate())
        conflux_tracing.add_predicate(BFTCommitPredicatePredicate())
        conflux_tracing.add_predicate(BFTLivenessPredicate(100))
        conflux_tracing.main()
    elif args.cmd == 'replay':
        conflux_tracing = TreeGraphTracing(
            nodes=2,
            replay=True,
            snapshot_file=args.snapshot_file,
            txs_file=args.txs_file)
        conflux_tracing.main()
