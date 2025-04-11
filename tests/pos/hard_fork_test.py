#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys

import rlp

sys.path.insert(1, os.path.join(sys.path[0], '..'))

import eth_utils
import os
import time
from eth_utils import keccak, decode_hex
import eth_abi

from conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr, parse_as_int
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.blocktools import encode_hex_0x


def address_to_topic(address):
    return "0x" + address[2:].zfill(64)


REGISTER_TOPIC = encode_hex_0x(keccak(b"Register(bytes32,bytes,bytes)"))
INCREASE_STAKE_TOPIC = encode_hex_0x(keccak(b"IncreaseStake(bytes32,uint64)"))


class HardforkTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        # 1e-9 chance of an empty round with no proposer.
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 / 300 * 20)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"
        self.conf_parameters["hydra_transition_height"] = 300
        self.conf_parameters["hydra_transition_number"] = 300
        self.conf_parameters["cip43_init_end_number"] = 500
        self.conf_parameters["pos_reference_enable_height"] = 1000
        self.conf_parameters["cip1559_transition_height"] = 1000
        self.conf_parameters["era_epoch_count"] = 200
        self.conf_parameters["pos_round_per_term"] = 10
        self.conf_parameters["pos_term_max_size"] = 100
        self.conf_parameters["pos_in_queue_locked_views"] = 60
        self.conf_parameters["pos_out_queue_locked_views"] = 60
        self.conf_parameters["sigma_fix_transition_number"] = 1000000
        self.conf_parameters["tanzanite_transition_height"] = 100
        self.conf_parameters["cip112_transition_height"] = 100

        self.rpc_timewait = 6000

    def setup_nodes(self):
        self.add_nodes(self.num_nodes)
        os.remove(os.path.join(self.options.tmpdir, "initial_nodes.json"))

        # start half of the nodes as archive nodes
        for i in range(self.num_nodes):
            self.start_node(i, phase_to_wait=None)

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log, latency_max=0)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.wait_for_recovery(["NormalSyncPhase"], 30)

    def run_test(self):
        # Pos contract enabled, stake and register in the first hard-fork phase.
        client = RpcClient(self.nodes[self.num_nodes - 1])
        client.generate_empty_blocks(300)
        sync_blocks(self.nodes)
        node_pos_identifier_list = []
        for i in range(self.num_nodes - 1):
            client = RpcClient(self.nodes[i])
            pos_identifier, _ = client.wait_for_pos_register()
            node_pos_identifier_list.append(pos_identifier)
            sync_blocks(self.nodes)
        client = RpcClient(self.nodes[self.num_nodes - 1])

        # generate blocks until we are after pos initialization and before pos start.
        best_epoch = client.epoch_number()
        client.generate_empty_blocks(600 - best_epoch)
        sync_blocks(self.nodes)

        voting_power_map = {}
        pub_keys_map = {}
        logs = client.get_logs(filter=Filter(from_epoch="earliest", to_epoch="latest_state",
                                             address=["0x0888000000000000000000000000000000000005"]))
        for log in logs:
            pos_identifier = log["topics"][1]
            if log["topics"][0] == REGISTER_TOPIC:
                bls_pub_key, vrf_pub_key = eth_abi.decode(["bytes", "bytes"], decode_hex(log["data"]))
                pub_keys_map[pos_identifier] = (encode_hex_0x(bls_pub_key), encode_hex_0x(vrf_pub_key))
            elif log["topics"][0] == INCREASE_STAKE_TOPIC:
                assert pos_identifier in pub_keys_map
                voting_power_map[pos_identifier] = parse_as_int(log["data"])
        with open(os.path.join(self.options.tmpdir, "public_keys"), "w") as f:
            for pos_identifier in pub_keys_map.keys():
                f.write(",".join([pub_keys_map[pos_identifier][0][2:], pub_keys_map[pos_identifier][1][2:],
                                  str(voting_power_map[pos_identifier])]) + "\n")
        initialize_tg_config(self.options.tmpdir, len(self.nodes), len(self.nodes), DEFAULT_PY_TEST_CHAIN_ID,
                             pkfile="public_keys", conflux_binary_path=self.options.conflux)

        # generate blocks until pos start
        self.nodes[0].test_generateEmptyBlocks(500)
        sync_blocks(self.nodes)
        pos_identifier, _ = client.wait_for_pos_register()
        client.generate_empty_blocks(400)
        sync_blocks(self.nodes)
        time.sleep(2)
        parent_hash = client.best_block_hash()
        for _ in range(100):
            parent_hash = client.node.test_generateCustomBlock(parent_hash, [], eth_utils.encode_hex(rlp.encode([])), False, ["0x01", "0x8804"])
        sync_blocks(self.nodes)

        # Check if stopped node will be retired
        STOP_INDEX = 0
        final_serving_round = self.nodes[0].test_posStopElection()
        stopped = False
        print("final_serving_round", final_serving_round)

        latest_pos_ref = self.latest_pos_ref()
        for i in range(55):
            if not stopped and int(client.pos_status()["latestCommitted"], 0) >= final_serving_round:
                print("stop node 0")
                self.stop_node(STOP_INDEX)
                stopped = True
            print(node_pos_identifier_list[STOP_INDEX])
            assert_ne(client.pos_get_account(node_pos_identifier_list[STOP_INDEX])["status"]["availableVotes"], 0)
            assert_equal(client.pos_get_account(node_pos_identifier_list[STOP_INDEX])["status"]["forceRetired"], None)
            print(i)
            if i == 10:
                self.stop_node(5, clean=True)
                self.start_node(5, phase_to_wait=None)
                self.nodes[5].wait_for_recovery(["NormalSyncPhase"], 30)
            if i == 12:
                self.maybe_restart_node(5, 1, 0)
            if i == 15:
                assert_equal(int(client.pos_get_account(pos_identifier)["status"]["availableVotes"], 0), 2000)
                client.pos_retire_self(2000)
            if i == 30:
                self.maybe_restart_node(5, 1, 1)
            # Retire node 3 after 5 min.
            # Generate enough PoW block for PoS to progress
            client.generate_empty_blocks(60)
            # Leave some time for PoS to reach consensus
            time.sleep(3)
            client.generate_empty_blocks(1)
            new_pos_ref = self.latest_pos_ref()
            if i >= 10:
                assert_ne(latest_pos_ref, new_pos_ref)

        client.wait_for_unstake(client.node.pow_sk)
        assert_greater_than(client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))),
                            10000 * 10 ** 18)
        assert_equal(int(client.pos_get_account(pos_identifier)["status"]["availableVotes"], 0), 0)

    def latest_pos_ref(self):
        best_hash = self.nodes[6].best_block_hash()
        block = self.nodes[6].cfx_getBlockByHash(best_hash, False)
        return block["posReference"]


if __name__ == '__main__':
    HardforkTest().main()
