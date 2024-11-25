#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from conflux.rpc import RpcClient
from conflux.utils import int_to_hex
from test_framework.test_framework import DefaultConfluxTestFramework
from test_framework.test_node import TestNode
from test_framework.util import *
PRIME = 1
BACKUP = 2
SAVE_SUFFIX = ".save"


class BackupVoterTest(DefaultConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.conf_parameters["vrf_proposal_threshold"] = '"{}"'.format(int_to_hex(int(2 ** 256 - 1)))
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        self.conf_parameters["pos_round_per_term"] = '10'
        self.conf_parameters["pos_started_as_voter"] = "false"

    def setup_nodes(self):
        self.add_nodes(self.num_nodes - 1)
        self.start_node(0, phase_to_wait=None, extra_args=["--pos-started-as-voter", "true"])
        self.start_node(PRIME)
        self.nodes[PRIME].test_posStartVoting(True)

        prime_node_pos_key_path = os.path.join(get_datadir_path(self.options.tmpdir, PRIME), 'blockchain_data', 'net_config', 'pos_key')
        backup_node_pos_key_path = os.path.join(get_datadir_path(self.options.tmpdir, BACKUP), 'blockchain_data', 'net_config', 'pos_key')
        os.makedirs(os.path.dirname(backup_node_pos_key_path))
        # Start nodes[2] as the backup voter node for nodes[1]
        self.nodes.append(
            TestNode(
                BACKUP,
                get_datadir_path(self.options.tmpdir, BACKUP),
                rpchost=None,
                confluxd=self.options.conflux,
                rpc_timeout=self.rpc_timewait,
            ))
        set_node_pos_config(self.options.tmpdir, BACKUP, setup_keys=False)
        shutil.copyfile(prime_node_pos_key_path, backup_node_pos_key_path)
        self.start_node(BACKUP, extra_args=["--pos-started-as-voter", "false"])

    def setup_network(self):
        self.setup_nodes()
        connect_sample_nodes(self.nodes, self.log, latency_max=0)
        sync_blocks(self.nodes)
        for node in self.nodes:
            node.wait_for_recovery(["NormalSyncPhase"], 30)

    def run_test(self):
        client = RpcClient(self.nodes[0])
        prime_node_safety_data_path = os.path.join(get_datadir_path(self.options.tmpdir, PRIME), "pos_db", "secure_storage.json")
        backup_node_safety_data_path = os.path.join(get_datadir_path(self.options.tmpdir, BACKUP), "pos_db", "secure_storage.json")
        # wait for the first block to be committed
        print(client.pos_status())
        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) >= 2)
        assert os.path.exists(prime_node_safety_data_path)
        assert self.nodes[PRIME].test_posVotingStatus()
        assert not self.nodes[BACKUP].test_posVotingStatus()
        self.nodes[PRIME].test_posStopVoting()
        time.sleep(2)
        assert not self.nodes[PRIME].test_posVotingStatus()
        assert not os.path.exists(prime_node_safety_data_path)
        assert os.path.exists(prime_node_safety_data_path + SAVE_SUFFIX)
        # Wait for the ongoing round to end.
        time.sleep(2)
        old_committed_round = client.pos_status()["latestCommitted"]
        old_voted_round = client.pos_status()["latestVoted"]
        time.sleep(5)
        new_voted_round = client.pos_status()["latestVoted"]
        # Ensure PRIME node actually does not vote
        assert_equal(old_voted_round, new_voted_round)
        assert not os.path.exists(prime_node_safety_data_path)
        shutil.copyfile(prime_node_safety_data_path + SAVE_SUFFIX, backup_node_safety_data_path + SAVE_SUFFIX)
        self.nodes[BACKUP].test_posStartVoting(False)
        assert self.nodes[BACKUP].test_posVotingStatus()
        assert os.path.exists(backup_node_safety_data_path)
        time.sleep(10)
        new_voted_round = client.pos_status()["latestVoted"]
        new_committed_round = client.pos_status()["latestCommitted"]
        # Ensure BACKUP node starts voting and PoS is making progress
        assert_greater_than(new_voted_round, old_voted_round)
        assert_greater_than(new_committed_round, old_committed_round)


if __name__ == '__main__':
    BackupVoterTest().main()
