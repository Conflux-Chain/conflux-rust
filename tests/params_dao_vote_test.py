#!/usr/bin/env python3
import json
import os

from eth_utils import decode_hex

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

    assert(type(dividend) is int)

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
    assert(type(old) is int)
    assert(type(votes) is int)
    assert(type(total_votes) is int)
    return old * power_two_frac(votes * 2 ** 64 // total_votes, neg) // 2 ** 96

BLOCKS_PER_YEAR = 2 * 60 * 60 * 24 * 365


class ParamsDaoVoteTest(ConfluxTestFramework):
    REQUEST_BASE = {
        'gas': CONTRACT_DEFAULT_GAS,
        'gasPrice': 1,
        'chainId': 1,
    }

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

    def get_nonce(self, sender, inc=True):
        if sender not in self.nonce_map:
            self.nonce_map[sender] = wait_for_initial_nonce_for_address(self.nodes[0], sender)
        else:
            self.nonce_map[sender] += 1
        return self.nonce_map[sender]

    def send_transaction(self, transaction, wait, check_status):
        self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[transaction]))
        if wait:
            self.wait_for_tx([transaction], check_status)

    def call_contract_function(self, contract, name, args, sender_key, value=None,
                               contract_addr=None, wait=False,
                               check_status=False,
                               storage_limit=0):
        if contract_addr:
            func = getattr(contract.functions, name)
        else:
            func = getattr(contract, name)
        attrs = {
            'nonce': self.get_nonce(priv_to_addr(sender_key)),
            **ParamsDaoVoteTest.REQUEST_BASE
        }
        if contract_addr:
            attrs['receiver'] = decode_hex(contract_addr)
            attrs['to'] = contract_addr
        else:
            attrs['receiver'] = b''
        tx_data = func(*args).buildTransaction(attrs)
        tx_data['data'] = decode_hex(tx_data['data'])
        tx_data['pri_key'] = sender_key
        tx_data['gas_price'] = tx_data['gasPrice']
        if value:
            tx_data['value'] = value
        tx_data.pop('gasPrice', None)
        tx_data.pop('chainId', None)
        tx_data.pop('to', None)
        tx_data['storage_limit'] = storage_limit
        transaction = create_transaction(**tx_data)
        self.send_transaction(transaction, wait, check_status)
        return transaction

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
        lock_value = 100
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


if __name__ == "__main__":
    ParamsDaoVoteTest().main()
