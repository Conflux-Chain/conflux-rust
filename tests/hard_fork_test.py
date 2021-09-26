#!/usr/bin/env python3
"""An example functional test
"""
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

class ExampleTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 7
        # 1e-9 chance of an empty round with no proposer.
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 / 300 * 20)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["dev_allow_phase_change_without_peer"] = "false"
        self.conf_parameters["unnamed_21autumn_transition_height"] = 300
        self.conf_parameters["unnamed_21autumn_transition_number"] = 300
        self.conf_parameters["unnamed_21autumn_cip43_init_end"] = 500
        self.conf_parameters["pos_reference_enable_height"] = 1000
        self.conf_parameters["era_epoch_count"] = 200
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
        for node in self.nodes:
            client = RpcClient(node)
            pos_identifier, _ = client.wait_for_pos_register()
            sync_blocks(self.nodes)
        client = RpcClient(self.nodes[self.num_nodes - 1])

        # generate blocks until we are after pos initialization and before pos start.
        best_epoch = client.epoch_number()
        client.generate_empty_blocks(600 - best_epoch)
        sync_blocks(self.nodes)

        voting_power_map = {}
        pub_keys_map = {}
        logs = client.get_logs(filter=Filter(from_epoch="earliest", to_epoch="latest_state", address=["0x0888000000000000000000000000000000000005"]))
        print("logs=", logs)
        for log in logs:
            pos_identifier = log["topics"][1]
            if log["topics"][0] == REGISTER_TOPIC:
                bls_pub_key, vrf_pub_key = eth_abi.decode_abi(["bytes", "bytes"], decode_hex(log["data"]))
                pub_keys_map[pos_identifier] = (encode_hex_0x(bls_pub_key), encode_hex_0x(vrf_pub_key))
                print(pub_keys_map[pos_identifier])
            elif log["topics"][0] == INCREASE_STAKE_TOPIC:
                assert pos_identifier in pub_keys_map
                voting_power_map[pos_identifier] = parse_as_int(log["data"])
        with open(os.path.join(self.options.tmpdir, "public_keys"), "w") as f:
            for pos_identifier in pub_keys_map.keys():
                f.write(",".join([pub_keys_map[pos_identifier][0][2:], pub_keys_map[pos_identifier][1][2:], str(voting_power_map[pos_identifier])]) + "\n")
        initialize_tg_config(self.options.tmpdir, len(self.nodes), len(self.nodes), DEFAULT_PY_TEST_CHAIN_ID, pkfile="public_keys")

        # generate blocks until pos start
        self.nodes[0].generate_empty_blocks(400)
        sync_blocks(self.nodes)

        latest_pos_ref = self.latest_pos_ref()
        for i in range(150):
            print(i)
            if i == 10:
                self.stop_node(5, clean=True)
                self.start_node(5, phase_to_wait=None)
                self.nodes[5].wait_for_recovery(["NormalSyncPhase"], 30)
            if i == 20:
                self.maybe_restart_node(5, 1, 0)
            if i == 50:
                client.pos_retire_self()
            if i == 100:
                self.maybe_restart_node(5, 1, 1)
            # Retire node 3 after 5 min.
            # Generate enough PoW block for PoS to progress
            self.nodes[0].generate_empty_blocks(60)
            # Leave some time for PoS to reach consensus
            time.sleep(3)
            self.nodes[0].generate_empty_blocks(1)
            new_pos_ref = self.latest_pos_ref()
            if i >= 10:
                assert_ne(latest_pos_ref, new_pos_ref)

        client.wait_for_unstake(client.node.pow_sk)
        assert client.get_balance(eth_utils.encode_hex(priv_to_addr(client.node.pow_sk))) > 10000 * 10**18
        # assert (self.nodes[0].getblockcount() == 6002)

    def latest_pos_ref(self):
        best_hash = self.nodes[0].best_block_hash()
        block = self.nodes[0].cfx_getBlockByHash(best_hash, False)
        return block["posReference"]

if __name__ == '__main__':
    ExampleTest().main()
