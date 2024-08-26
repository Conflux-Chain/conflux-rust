#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys

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
from test_framework.block_gen_thread import PoWGenerateThread


def address_to_topic(address):
    return "0x" + address[2:].zfill(64)


REGISTER_TOPIC = encode_hex_0x(keccak(b"Register(bytes32,bytes,bytes)"))
INCREASE_STAKE_TOPIC = encode_hex_0x(keccak(b"IncreaseStake(bytes32,uint64)"))


class RetireParamHardforkTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.conf_parameters["pos_pivot_decision_defer_epoch_count"] = '120'
        # self.conf_parameters["log_level"] = '"trace"'
        self.conf_parameters["cip43_init_end_number"] = 1
        self.conf_parameters["era_epoch_count"] = 200
        self.conf_parameters["pos_round_per_term"] = 6
        self.conf_parameters["pos_term_max_size"] = 100
        self.conf_parameters["pos_in_queue_locked_views"] = 36
        self.conf_parameters["pos_out_queue_locked_views"] = 36
        self.conf_parameters["pos_cip99_transition_view"] = 72
        self.conf_parameters["pos_cip99_in_queue_locked_views"] = 66
        self.conf_parameters["pos_cip99_out_queue_locked_views"] = 6
        self.conf_parameters["pos_cip136_transition_view"] = 144
        self.conf_parameters["pos_cip136_round_per_term"] = 12
        self.conf_parameters["pos_cip136_in_queue_locked_views"] = 132
        self.conf_parameters["pos_cip136_out_queue_locked_views"] = 12
        self.rpc_timewait = 6000

    def run_test(self):
        client = RpcClient(self.nodes[0])
        _, pos_identifier = client.node.test_posRegister(int_to_hex(1000))

        def unlock_list():
            client.generate_blocks(60)
            return client.pos_get_account(pos_identifier)["status"]["outQueue"]

        def wait():
            client.generate_empty_blocks(60)
            return int(client.pos_status()["epoch"], 0) > 6
        wait_until(wait, timeout=120)
        self.log.info("Retire half votes")
        old_view = int(client.pos_status()["latestCommitted"], 0)
        client.pos_retire_self(500)

        wait_until(lambda: len(unlock_list()) == 1)
        out_queue = unlock_list()
        unlock_view = int(out_queue[0]["endBlockNumber"], 0)
        print(unlock_view, old_view)
        assert_greater_than_or_equal(unlock_view - old_view, self.conf_parameters["pos_out_queue_locked_views"])

        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) > self.conf_parameters["pos_cip99_transition_view"], timeout=120)
        self.log.info("Retire again")
        old_view = int(client.pos_status()["latestCommitted"], 0)
        client.pos_retire_self(500)
        wait_until(lambda: unlock_list() != out_queue and len(unlock_list()) == 1)
        out_queue = unlock_list()
        unlock_view = int(out_queue[0]["endBlockNumber"], 0)
        print(unlock_view, old_view)
        assert_greater_than_or_equal(unlock_view - old_view, self.conf_parameters["pos_cip99_out_queue_locked_views"])
        assert_greater_than(self.conf_parameters["pos_out_queue_locked_views"], unlock_view - old_view)

        old_epoch = int(client.pos_status()["epoch"], 0)
        client.node.test_posStopVoting()
        wait_until(lambda: client.pos_get_account(pos_identifier)["status"]["forceRetired"] is not None)
        new_epoch = int(client.pos_status()["epoch"], 0)
        print(new_epoch, old_epoch)
        assert_greater_than_or_equal(new_epoch - old_epoch, 3)

        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) > self.conf_parameters["pos_cip136_transition_view"], timeout=120)
        old_epoch = int(client.pos_status()["epoch"], 0)
        check_view = self.conf_parameters["pos_cip136_transition_view"] + self.conf_parameters["pos_cip136_round_per_term"]
        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) > check_view, timeout=120)
        status = client.pos_status()
        assert_greater_than(check_view + self.conf_parameters["pos_cip136_round_per_term"], int(status["latestCommitted"], 0))
        assert_equal(int(status["epoch"], 0), old_epoch + 1)
        wait_until(lambda: int(client.pos_status()["latestCommitted"], 0) > check_view + 7 * self.conf_parameters["pos_cip136_round_per_term"], timeout=240)
        status = client.pos_status()
        assert_equal(int(status["epoch"], 0), old_epoch + 8)


if __name__ == '__main__':
    RetireParamHardforkTest().main()
