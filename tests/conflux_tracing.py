#!/usr/bin/env python3
import random
import threading
import json
import enum
import copy
import argparse
import eth_utils
import rlp

from conflux.rpc import RpcClient
from test_framework.test_framework import ConfluxTestFramework
from test_framework.blocktools import create_block_with_nonce
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *

DEFAULT_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000'
NUM_TX_PER_BLOCK = 10


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
        node.wait_for_recovery(["NormalSyncPhase", "CatchUpSyncBlockPhase"], wait_time=100000)

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
        self.past_era_weight = json_data['pastEraWeight']
        self.era_block_hash = json_data['eraBlockHash']
        self.stable = json_data['stable']
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
            self.past_era_weight == other.past_era_weight and \
            self.block_status == other.block_status and \
            self.adaptive == other.adaptive and \
            self.stable == other.stable

    def __str__(self):
        return "ConsensusBlockStatus(\
                hash={}, \
                best_block_hash={}, \
                block_status={}, \
                past_era_weight={}, \
                era_block={}, \
                stable={}, \
                adaptive={})".format(
            self.hash,
            self.best_block_hash,
            self.block_status,
            self.past_era_weight,
            self.era_block,
            self.stable,
            self.adaptive)


class ConsensusExecutionStatus(object):
    def __init__(self, json_data):
        self.hash = json_data['blockHash']
        self.deferred_state_root = json_data['deferredStateRoot']
        self.deferred_receipt_root = json_data['deferredReceiptRoot']
        self.deferred_logs_bloom_hash = json_data['deferredLogsBloomHash']
        self.state_valid = json_data['stateValid']

    def __eq__(self, other):
        return self.hash == other.hash and \
            self.deferred_state_root == other.deferred_state_root and \
            self.deferred_receipt_root == other.deferred_receipt_root and \
            self.deferred_logs_bloom_hash == other.deferred_logs_bloom_hash and \
            self.state_valid == other.state_valid


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
                assert block.stable == verified_block.stable, "peer[{}] block[{}] stable[{}], expect [{}]".format(
                    self.peer_id, block.hash, block.stable, verified_block.stable)
                assert block.adaptive == verified_block.adaptive, "peer[{}] block[{}] adaptive[{}], expect [{}]".format(
                    self.peer_id, block.hash, block.adaptive, verified_block.adaptive)
                assert block.era_block_hash == verified_block.era_block_hash or \
                    block.era_block_hash == DEFAULT_HASH, "peer[{}] block[{}] era_block_hash[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.era_block_hash, verified_block.era_block_hash)
                assert block.past_era_weight == verified_block.past_era_weight, "peer[{}] block[{}] past_era_weight[{}], expect [{}]".format(
                    self.peer_id, block.hash, block.past_era_weight, verified_block.past_era_weight)
        elif block.hash in self.block_status_unverified:
            unverified_block = self.block_status_unverified[block.hash]
            if unverified_block.block_status == BlockStatus.Pending:
                self.block_status_unverified[block.hash] = block
            else:
                if block.block_status != BlockStatus.Pending:
                    assert block.block_status == unverified_block.block_status, "peer[{}] block[{}] status[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.block_status, unverified_block.block_status)
                    assert block.stable == unverified_block.stable, "peer[{}] block[{}] stable[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.stable, unverified_block.stable)
                    assert block.adaptive == unverified_block.adaptive, "peer[{}] block[{}] adaptive[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.adaptive, unverified_block.adaptive)
                    assert block.era_block_hash == unverified_block.era_block_hash or \
                        block.era_block_hash == DEFAULT_HASH or \
                        unverified_block.era_block_hash == DEFAULT_HASH, "peer[{}] block[{}] era_block_hash[{}], expect [{}]".format(
                            self.peer_id, block.hash, block.era_block_hash, unverified_block.era_block_hash)
                    assert block.past_era_weight == unverified_block.past_era_weight, "peer[{}] block[{}] past_era_weight[{}], expect [{}]".format(
                        self.peer_id, block.hash, block.past_era_weight, unverified_block.past_era_weight)
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
            assert exec.state_valid == verified_exec.state_valid, "peer[{}] block[{}] state_valid[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.state_valid, verified_exec.state_valid)
        elif exec.hash in self.exec_status_unverified:
            unverified_exec = self.exec_status_unverified[exec.hash]
            assert exec.deferred_state_root == unverified_exec.deferred_state_root, "peer[{}] block[{}] deferred_state_root[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_state_root, unverified_exec.deferred_state_root)
            assert exec.deferred_receipt_root == unverified_exec.deferred_receipt_root, "peer[{}] block[{}] deferred_receipt_root[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_receipt_root, unverified_exec.deferred_receipt_root)
            assert exec.deferred_logs_bloom_hash == unverified_exec.deferred_logs_bloom_hash, "peer[{}] block[{}] deferred_logs_bloom_hash[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.deferred_logs_bloom_hash, unverified_exec.deferred_logs_bloom_hash)
            assert exec.state_valid == unverified_exec.state_valid, "peer[{}] block[{}] state_valid[{}], expect[{}]".format(
                self.peer_id, exec.hash, exec.state_valid, unverified_exec.state_valid)
        else:
            self.exec_status_unverified[exec.hash] = exec


class Snapshot(object):
    def __init__(self, peer_id, genesis):
        self.genesis = genesis
        self.peer_id = peer_id
        self.consensus = ConsensusSnapshot(peer_id)
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
        self.event_list.append(StartEvent())

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


class ConfluxTracing(ConfluxTestFramework):
    def __init__(
            self,
            nodes=11,
            crash_timeout=10,
            start_timeout=10,
            blockgen_timeout=0.25,
            snapshot_timeout=5.0,
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
                    self._stopped_peers.remove(chosen_peer)
                    self.log.info("starting {}".format(chosen_peer))
                    self.start_node(chosen_peer, phase_to_wait=None)
                    self._snapshots[chosen_peer].start()
                    self.log.info("started {}".format(chosen_peer))
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
                catch_up_peers = alive_peer_indices.get('CatchUpSyncBlockPhase', [])
                if (len(normal_peers) - 1) * 2 <= len(self.nodes):
                    return
                alive_peer_indices = normal_peers + catch_up_peers
                # We need peer[0] to run forever as a reference
                chosen_peer = alive_peer_indices[random.randint(
                    1, len(alive_peer_indices) - 1)]
                self.log.info("stopping {}".format(chosen_peer))
                # retrieve new ready blocks before stopping it
                new_blocks = self.nodes[chosen_peer].sync_graph_state()
                self._snapshots[chosen_peer].new_blocks(new_blocks['readyBlockVec'])
                self.stop_node(chosen_peer)
                self._stopped_peers.append(chosen_peer)
                self._snapshots[chosen_peer].stop()
                self.log.info("stopped {}".format(chosen_peer))
        except Exception as e:
            self.log.info('got exception[{}] during crash'.format(repr(e)))
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
            tx = client.new_tx(receiver=addr, nonce=nonce, value=0, gas=tx_gas, data=b'')
            txs.append(tx)
        return txs

    def _generate_block(self):
        """
            random select an alive peer and generate a block
        """
        try:
            with self._peer_lock:
                alive_peer_indices = self._retrieve_alive_peers(["NormalSyncPhase"])
                alive_peer_indices = alive_peer_indices.get('NormalSyncPhase', [])
                if self.options.archive:
                    assert len(alive_peer_indices) * \
                        2 > self.num_nodes, "alive[{}] total[{}]".format(len(alive_peer_indices), self.num_nodes)
                chosen_peer = alive_peer_indices[random.randint(
                    0, len(alive_peer_indices) - 1)]
                txs = self._generate_txs(chosen_peer, NUM_TX_PER_BLOCK)
                if random.randint(1, 100) <= 40:
                    # this will generate a partial invalid block
                    block_hash = RpcClient(self.nodes[chosen_peer]).generate_block_with_fake_txs(txs, True)
                else:
                    block_hash = RpcClient(self.nodes[chosen_peer]).generate_block_with_fake_txs(txs)
                self._block_txs[block_hash] = eth_utils.encode_hex(rlp.encode(txs))
                self.log.info("peer[%d] generate block[%s]", chosen_peer, block_hash)
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
                    snapshot.update(delta)
                    snapshot.new_blocks(new_blocks['readyBlockVec'])
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
            "log_level": "\"debug\"",
            "generate_tx": "true",
            "generate_tx_period_us": "100000",
            "enable_state_expose": "true",
            "era_epoch_count": 50,
            "era_checkpoint_gap": 50
        }

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        if self.options.archive:
            self.start_nodes()
        else:
            self.start_node(0)
            for i in range(1, self.num_nodes):
                self.start_node(i, extra_args=["--full"], phase_to_wait=None)

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
                default_config["TOTAL_COIN"] / self.num_nodes) - 21000, receiver=encode_hex(addr), nonce=i)
            client.send_tx(tx)

    def persist_snapshot(self):
        self.log.info("saving txs to txs.json")
        with open('txs.json', 'w') as fp:
            fp.write(json.dumps(self._block_txs))
        self.log.info("txs saved to txs.json")
        for (index, snapshot) in enumerate(self._snapshots):
            self.log.info('saving snapshot {} to snapshot_{}.json'.format(index, index))
            with open('snapshot_{}.json'.format(index), 'w') as fp:
                fp.write(json.dumps(snapshot.to_json()))
            self.log.info('snapshot {} saved to snapshot_{}.json'.format(index, index))

    def run_test(self):
        if self._replay:
            self.replay(self._snapshot_file)
            return
        genesis_hash = self.nodes[0].best_block_hash()
        crash_timer = Timer(self._crash_timeout, self._random_crash)
        start_timer = Timer(self._start_timeout, self._random_start)
        blockgen_timer = Timer(self._blockgen_timeout, self._generate_block)
        snapshot_timer = Timer(self._snapshot_timeout, self._retrieve_snapshot)

        self._snapshots = [Snapshot(i, genesis_hash) for i in range(len(self.nodes))]
        self._peer_nonce = [0] * len(self.nodes)
        self.setup_balance()

        crash_timer.start()
        start_timer.start()
        blockgen_timer.start()
        snapshot_timer.start()

        # TODO: we may make it run forever
        time.sleep(200000)

        crash_timer.cancel()
        start_timer.cancel()
        blockgen_timer.cancel()
        snapshot_timer.cancel()

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
            '-archive',
            '--archive',
            dest='archive',
            type=int,
            default=1,
            help='archive node mode or full node mode')
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

    def replay(self, file_path):
        snapshot = json.load(open(file_path, 'r'))
        genesis_hash = snapshot['genesis']
        events = snapshot['events']
        self.setup_balance()

        node = self.nodes[0]
        self._genesis_hash = node.best_block_hash()
        assert genesis_hash == self._genesis_hash
        for event in events:
            if event['name'] == StartEvent().name():
                self.log.info("stop")
                StartEvent().execute(node)
            elif event['name'] == StopEvent().name():
                self.log.info("start")
                StopEvent().execute(node)
            else:
                self.log.info("new block[{}]".format(event['hash']))
                txs = self._block_txs[event['hash']]
                NewBlockEvent(
                    hash=event['hash'],
                    parent=event['parent'],
                    referees=event['referees'],
                    nonce=event['nonce'],
                    timestamp=event['timestamp'],
                    adaptive=event['adaptive'],
                    txs=txs
                ).execute(node)


class BlockStatusPredicate(Predicate):
    def __init__(self):
        super().__init__()

    def verify_blocks(self, blocks):
        for i in range(1, len(blocks)):
            assert blocks[i] == blocks[0]

    def verify_snapshots(self, snapshots, hashes):
        for h in hashes:
            blocks = [snapshot.consensus.block_status_unverified[h] for snapshot in snapshots]
            self.verify_blocks(blocks)
            for (snapshot, block) in zip(snapshots, blocks):
                if block.block_status != BlockStatus.Pending:
                    snapshot.consensus.block_status_verified[h] = block
                    del snapshot.consensus.block_status_unverified[h]

    def __call__(self, snapshots, stopped_peers):
        verified = {}
        for snapshot in snapshots:
            for (k, v) in snapshot.consensus.block_status_verified.items():
                if k in verified:
                    assert verified[k] == v
                else:
                    verified[k] = v
        verified_hashes = set(verified.keys())
        verifiable_hashes = None
        verifiable_hashes_with_stopped = None
        alive_snapshots = []
        for (i, snapshot) in enumerate(snapshots):
            unverified_hashes = set(snapshot.consensus.block_status_unverified.keys())
            for h in unverified_hashes.intersection(verified_hashes):
                assert verified[h] == snapshot.consensus.block_status_unverified[h]
                snapshot.consensus.block_status_verified[h] = verified[h]
                del snapshot.consensus.block_status_unverified[h]
            if verifiable_hashes_with_stopped is None:
                verifiable_hashes_with_stopped = copy.deepcopy(unverified_hashes)
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


class ExecutionStatusPredicate(Predicate):
    def __init__(self):
        super().__init__()

    def verify_blocks(self, blocks):
        for i in range(1, len(blocks)):
            assert blocks[i] == blocks[0]

    def verify_snapshots(self, snapshots, hashes):
        for h in hashes:
            blocks = [snapshot.consensus.exec_status_unverified[h] for snapshot in snapshots]
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
            unverified_hashes = set(snapshot.consensus.exec_status_unverified.keys())
            for h in unverified_hashes.intersection(verified_hashes):
                assert verified[h] == snapshot.consensus.exec_status_unverified[h]
                snapshot.consensus.exec_status_verified[h] = verified[h]
                del snapshot.consensus.exec_status_unverified[h]
            if verifiable_hashes_with_stopped is None:
                verifiable_hashes_with_stopped = copy.deepcopy(unverified_hashes)
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


def parse_args():
    parser = argparse.ArgumentParser()
    ConfluxTracing().add_options(parser)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.cmd == 'run':
        conflux_tracing = ConfluxTracing(
            nodes=args.nodes,
            crash_timeout=args.crash_timeout,
            start_timeout=args.start_timeout,
            blockgen_timeout=args.blockgen_timeout,
            snapshot_timeout=args.snapshot_timeout)
        conflux_tracing.add_predicate(BlockStatusPredicate())
        conflux_tracing.add_predicate(ExecutionStatusPredicate())
        conflux_tracing.main()
    elif args.cmd == 'replay':
        conflux_tracing = ConfluxTracing(
            nodes=2,
            replay=True,
            snapshot_file=args.snapshot_file,
            txs_file=args.txs_file)
        conflux_tracing.main()
