#!/usr/bin/env python3
import json
import os

import eth_utils
from eth_utils import decode_hex
from test_framework.simple_rpc_proxy import ReceivedErrorResponseError
from web3 import Web3

from conflux.config import default_config
from conflux.messages import Transactions
from conflux.rpc import RpcClient, stake_tx_data, lock_tx_data, get_contract_function_data
from conflux.transactions import CONTRACT_DEFAULT_GAS
from conflux.utils import int_to_hex, priv_to_addr
from test_framework.blocktools import create_transaction, wait_for_initial_nonce_for_address
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import get_contract_instance, assert_equal
import numpy as np


def sqrt(n: int):
    x = int(np.sqrt(float(n)))
    for _ in range(4):
        x = (x + n // x) // 2
    assert (x * x <= n)
    assert ((x + 1) * (x + 1) > n)
    return x


def power_two_frac(dividend: int, neg: bool):
    base = 1 << 254

    assert (type(dividend) is int)

    for _ in range(64):
        if dividend % 2 != 0:
            if neg:
                base = base // 2
            else:
                base = base * 2

        base = sqrt(base)
        base <<= 127
        dividend //= 2
        # print(base)

    return base >> (254 - 96)


def update_value(old: int, votes: int, total_votes: int, neg: bool):
    assert (type(old) is int)
    assert (type(votes) is int)
    assert (type(total_votes) is int)
    return old * power_two_frac(votes * 2 ** 64 // total_votes, neg) // 2 ** 96


BLOCKS_PER_YEAR = 2 * 60 * 60 * 24 * 365


class ParamsDaoVoteTest(ConfluxTestFramework):
    def __init__(self):
        super().__init__()
        self.nonce_map = {}
        self.genesis_priv_key = default_config['GENESIS_PRI_KEY']
        self.genesis_addr = priv_to_addr(self.genesis_priv_key)
        self.balance_map = {self.genesis_priv_key: default_config['TOTAL_COIN']}

    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["params_dao_vote_period"] = "10"
        self.conf_parameters["dao_vote_transition_number"] = "1"
        self.conf_parameters["dao_vote_transition_height"] = "1"

    def run_test(self):
        file_dir = os.path.dirname(os.path.realpath(__file__))
        control_contract_file_path = os.path.join(file_dir, "../internal_contract/metadata/ParamsControl.json")
        control_contract_dict = json.loads(open(control_contract_file_path, "r").read())
        params_control_contract = get_contract_instance(contract_dict=control_contract_dict)

        client = RpcClient(self.nodes[0])
        client.generate_empty_blocks(1)[0]
        client.generate_empty_blocks(40)
        current_interest_rate = int(client.get_interest_rate("0x1"), 0) // BLOCKS_PER_YEAR
        current_base_reward = int(client.get_block_reward_info("0x1")[0]["baseReward"], 0)

        # Check if the parameters remain unchanged without vote
        assert_equal(int(client.get_interest_rate(int_to_hex(20)), 0), current_interest_rate * BLOCKS_PER_YEAR)
        assert_equal(int(client.get_block_reward_info(int_to_hex(20))[0]["baseReward"], 0), current_base_reward)

        # stake and lock CFX
        # By default, we have one pos account that stakes 2_000_000 CFX for PoS, so 100000 vote locks for one year
        # is just sufficient for parameter change. Here we lock 200000 because we may vote with half votes.
        lock_value = 200000
        tx = client.new_tx(data=stake_tx_data(lock_value), value=0,
                           receiver="0x0888000000000000000000000000000000000002", gas=CONTRACT_DEFAULT_GAS)
        client.send_tx(tx, wait_for_receipt=True)
        current_block_number = int(client.get_status()["blockNumber"], 0)
        locked_time = 5 * 15_768_000  # MINED_BLOCK_COUNT_PER_QUARTER
        tx = client.new_tx(data=lock_tx_data(lock_value, current_block_number + locked_time), value=0,
                           receiver="0x0888000000000000000000000000000000000002", gas=CONTRACT_DEFAULT_GAS)
        client.send_tx(tx, wait_for_receipt=True)
        account2_addr, account2_priv = client.rand_account()
        tx = client.new_tx(value=lock_value * 2 * 10 ** 18, receiver=account2_addr)
        client.send_tx(tx, wait_for_receipt=True)
        tx = client.new_tx(priv_key=account2_priv, data=stake_tx_data(lock_value), value=0,
                           receiver="0x0888000000000000000000000000000000000002", gas=CONTRACT_DEFAULT_GAS)
        client.send_tx(tx, wait_for_receipt=True)
        current_block_number = int(client.get_status()["blockNumber"], 0)
        locked_time = 5 * 15_768_000  # MINED_BLOCK_COUNT_PER_QUARTER
        tx = client.new_tx(priv_key=account2_priv, data=lock_tx_data(lock_value, current_block_number + locked_time),
                           value=0, receiver="0x0888000000000000000000000000000000000002", gas=CONTRACT_DEFAULT_GAS)
        client.send_tx(tx, wait_for_receipt=True)
        lock_value = lock_value * 10 ** 18

        # Vote for both increase
        vote_period = int(self.conf_parameters["params_dao_vote_period"])
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, lock_value, 0]), (1, [0, lock_value, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)

        client.send_tx(tx, wait_for_receipt=True)
        # Generate enough blocks to get pow reward with new parameters.
        client.generate_empty_blocks(40)
        best_epoch = client.epoch_number()
        current_base_reward = current_base_reward * 2
        current_interest_rate = current_interest_rate * 2
        assert_equal(int(client.get_block_reward_info(int_to_hex(best_epoch - 17))[0]["baseReward"], 0),
                     current_base_reward)
        assert_equal(int(client.get_interest_rate(), 0), current_interest_rate * BLOCKS_PER_YEAR)

        # Vote for a single parameter
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(1, [0, 0, lock_value])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        # Generate enough blocks to get pow reward with new parameters.
        client.generate_empty_blocks(40)
        best_epoch = client.epoch_number()
        current_interest_rate = current_interest_rate // 2
        assert_equal(int(client.get_block_reward_info(int_to_hex(best_epoch - 17))[0]["baseReward"], 0),
                     current_base_reward)
        assert_equal(int(client.get_interest_rate(), 0), current_interest_rate * BLOCKS_PER_YEAR)
        vote_params = client.get_params_from_vote()
        assert_equal(int(vote_params["interestRate"], 0), current_interest_rate)
        assert_equal(int(vote_params["powBaseReward"], 0), current_base_reward)

        # Two accounts vote
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, 0, lock_value]), (1, [lock_value, 0, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        tx_hash1 = client.send_tx(tx)
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [lock_value, 0, 0]), (1, [0, lock_value, 0])]])
        tx = client.new_tx(priv_key=account2_priv, data=data, value=0,
                           receiver="0x0888000000000000000000000000000000000007", gas=CONTRACT_DEFAULT_GAS,
                           storage_limit=1024)
        tx_hash2 = client.send_tx(tx)
        client.wait_for_receipt(tx_hash1, state_before_wait=True)
        client.wait_for_receipt(tx_hash2)
        # Generate enough blocks to get pow reward with new parameters.
        client.generate_empty_blocks(40)
        best_epoch = client.epoch_number()
        # half vote for decrease
        current_base_reward = update_value(current_base_reward, lock_value, lock_value * 2, True)
        # half vote for increase
        current_interest_rate = update_value(current_interest_rate, lock_value, lock_value * 2, False)
        assert_equal(int(client.get_block_reward_info(int_to_hex(best_epoch - 17))[0]["baseReward"], 0),
                     current_base_reward)
        assert_equal(int(client.get_interest_rate(), 0), current_interest_rate * BLOCKS_PER_YEAR)
        vote_params = client.get_params_from_vote()
        assert_equal(int(vote_params["interestRate"], 0), current_interest_rate)
        assert_equal(int(vote_params["powBaseReward"], 0), current_base_reward)

        # Replace old votes
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        data = get_contract_function_data(params_control_contract, "castVote", args=[version, [
            (1, [int(lock_value / 4), 0, int(lock_value / 2)]), (0, [int(lock_value / 2), int(lock_value / 2), 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        next_nonce = tx.nonce + 1
        client.send_tx(tx)
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [int(lock_value / 4), 0, int(lock_value / 2)])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024, nonce=next_nonce)
        client.send_tx(tx, wait_for_receipt=True)
        # Generate enough blocks to get pow reward with new parameters.
        client.generate_empty_blocks(40)
        best_epoch = client.epoch_number()
        current_base_reward = update_value(current_base_reward, lock_value // 2, lock_value * 3 // 4, True)
        current_interest_rate = update_value(current_interest_rate, lock_value // 2, lock_value * 3 // 4, True)

        assert_equal(int(client.get_block_reward_info(int_to_hex(best_epoch - 17))[0]["baseReward"], 0),
                     current_base_reward)
        assert_equal(int(client.get_interest_rate(), 0), current_interest_rate * BLOCKS_PER_YEAR)
        vote_params = client.get_params_from_vote()
        assert_equal(int(vote_params["interestRate"], 0), current_interest_rate)
        assert_equal(int(vote_params["powBaseReward"], 0), current_base_reward)

        # Test invalid votes
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        # not enough voting power for a single vote
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, lock_value + 1, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        # not enough voting power for the total votes
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, lock_value, 0]), (1, [1, lock_value, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        # old version
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period)
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, lock_value, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        # future version
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 2
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, lock_value, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        # Invalid vote indices
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(2, [0, lock_value, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        # Duplicate votes
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, 1, 0]), (0, [1, 0, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        # Generate enough blocks to get pow reward with new parameters.
        client.generate_empty_blocks(40)
        best_epoch = client.epoch_number()
        assert_equal(int(client.get_block_reward_info(int_to_hex(best_epoch - 17))[0]["baseReward"], 0),
                     current_base_reward)
        assert_equal(int(client.get_interest_rate(), 0), current_interest_rate * BLOCKS_PER_YEAR)
        vote_params = client.get_params_from_vote()
        assert_equal(int(vote_params["interestRate"], 0), current_interest_rate)
        assert_equal(int(vote_params["powBaseReward"], 0), current_base_reward)

        # Vote with not sufficient vote and check if the parameter remains unchanged.
        min_vote = int(2_000_000 * 0.05) * 10 ** 18
        block_number = int(client.get_status()["blockNumber"], 0)
        version = int(block_number / vote_period) + 1
        # Vote with enough votes for PoS interest but not enough votes for PoW reward.
        data = get_contract_function_data(params_control_contract, "castVote",
                                          args=[version, [(0, [0, min_vote - 1, 0]), (1, [0, min_vote, 0])]])
        tx = client.new_tx(data=data, value=0, receiver="0x0888000000000000000000000000000000000007",
                           gas=CONTRACT_DEFAULT_GAS, storage_limit=1024)
        client.send_tx(tx, wait_for_receipt=True)
        current_interest_rate = current_interest_rate * 2
        client.generate_empty_blocks(40)
        best_epoch = client.epoch_number()
        assert_equal(int(client.get_block_reward_info(int_to_hex(best_epoch - 17))[0]["baseReward"], 0),
                     current_base_reward)
        assert_equal(int(client.get_interest_rate(), 0), current_interest_rate * BLOCKS_PER_YEAR)
        vote_params = client.get_params_from_vote()
        assert_equal(int(vote_params["interestRate"], 0), current_interest_rate)
        assert_equal(int(vote_params["powBaseReward"], 0), current_base_reward)

        # test reading interfaces
        block_number = int(client.get_status()["blockNumber"], 0)
        round = int(block_number / vote_period)
        data = get_contract_function_data(params_control_contract, "currentRound", args=[])
        assert_equal(round, int(client.call("0x0888000000000000000000000000000000000007", eth_utils.encode_hex(data)), 0))
        data = get_contract_function_data(params_control_contract, "posStakeForVotes", args=[round])
        assert_equal(2_000_000 * 10 ** 18, int(client.call("0x0888000000000000000000000000000000000007", eth_utils.encode_hex(data)), 0))
        data = get_contract_function_data(params_control_contract, "totalVotes", args=[round])
        total = client.call("0x0888000000000000000000000000000000000007", eth_utils.encode_hex(data))
        data = get_contract_function_data(params_control_contract, "readVote", args=[Web3.to_checksum_address(client.GENESIS_ADDR)])
        vote = client.call("0x0888000000000000000000000000000000000007", eth_utils.encode_hex(data))
        assert_equal(total, vote)


if __name__ == "__main__":
    ParamsDaoVoteTest().main()
