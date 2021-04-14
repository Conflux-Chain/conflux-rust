#!/usr/bin/env python3
from rlp.sedes import Binary, BigEndianInt

from conflux import utils, trie
from conflux.rpc import RpcClient
from conflux.trie import compute_transaction_root_for_single_transaction
from conflux.utils import encode_hex, bytes_to_int, int_to_hex, str_to_bytes
from test_framework.blocktools import create_block, create_transaction, create_chain_of_blocks
from test_framework.test_framework import ConfluxTestFramework
from test_framework.mininode import *
from test_framework.util import *


CHAIN_LEN = 400
class InvalidBodyNode(DefaultNode):
    def __init__(self):
        super().__init__()
        correct_chain = create_chain_of_blocks(parent_hash=self.genesis.hash, parent_height=0, count=CHAIN_LEN)
        invalid_tx = create_transaction(chain_id=0)
        invalid_body_block = create_block(parent_hash=self.genesis.hash, height=1, transactions=[invalid_tx],
                                          transaction_root=compute_transaction_root_for_single_transaction(invalid_tx.hash))
        invalid_chain_suffix = create_chain_of_blocks(parent_hash=invalid_body_block.hash, parent_height=1,
                                                      count=CHAIN_LEN)
        last_block = create_block(parent_hash=invalid_chain_suffix[-1].hash, height=CHAIN_LEN + 2,
                                  referee_hashes=[correct_chain[-1].hash])
        invalid_chain = [invalid_body_block] + invalid_chain_suffix + [last_block]
        self.block_map = {self.genesis.hash: self.genesis}
        self.epoch_map = {0: self.genesis.hash}
        for i in range(1, CHAIN_LEN + 3):
            b = invalid_chain[i-1]
            self.block_map[b.hash] = b
            self.epoch_map[i] = {b.hash}
        for b in correct_chain:
            self.block_map[b.hash] = b
            self.epoch_map[CHAIN_LEN + 2].add(b.hash)
        self.invalid_block = invalid_body_block.hash

        self.set_callback(GET_BLOCK_HEADERS, self.__class__.on_get_block_headers)
        self.best_block_hash = last_block.hash

    def on_get_block_hashes_by_epoch(self, msg: GetBlockHashesByEpoch):
        hashes = []
        for epoch in msg.epochs:
            hashes.extend(self.epoch_map[epoch])
        resp = BlockHashes(reqid=msg.reqid, hashes=hashes)
        self.send_protocol_msg(resp)

    def on_get_blocks(self, msg: GetBlocks):
        blocks = []
        for h in msg.hashes:
            blocks.append(self.block_map[h])
        resp = Blocks(reqid=msg.reqid, blocks=blocks)
        self.send_protocol_msg(resp)

    def on_get_block_headers(self, msg: GetBlockHeaders):
        blocks = []
        for h in msg.hashes:
            blocks.append(self.block_map[h].block_header)
        resp = BlockHeaders(reqid=msg.reqid, headers=blocks)
        self.send_protocol_msg(resp)

    def send_status(self):
        status = Status(
            ChainIdParams(self.chain_id),
            self.genesis.block_header.hash, CHAIN_LEN + 2, 0, [self.best_block_hash])
        self.send_protocol_msg(status)

class InvalidBodySyncTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"

    def setup_network(self):
        self.add_nodes(self.num_nodes)
        for i in range(self.num_nodes):
            self.nodes[i].start(extra_args=["--full"])
            self.nodes[i].wait_for_rpc_connection()
            self.nodes[i].wait_for_nodeid()

    def run_test(self):
        conn0 = InvalidBodyNode()
        conn1 = DefaultNode()
        self.nodes[1].add_p2p_connection(conn1)
        network_thread_start()
        conn1.wait_for_status()
        for (h, b) in conn0.block_map.items():
            if h != conn0.invalid_block:
                conn1.send_protocol_msg(NewBlock(block=b))
        wait_for_block_count(self.nodes[1], CHAIN_LEN + 1)

        self.nodes[0].add_p2p_connection(conn0)
        conn0.wait_for_status()
        connect_nodes(self.nodes, 0, 1)

        self.nodes[0].wait_for_phase(["NormalSyncPhase"], wait_time=120)
        wait_until(lambda: int(self.nodes[0].cfx_getStatus()["epochNumber"], 0) == CHAIN_LEN)


if __name__ == "__main__":
    InvalidBodySyncTest().main()
