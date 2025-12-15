from itertools import product
import random
import pytest
from conflux_web3 import Web3
from web3.exceptions import Web3RPCError
from typing import cast
from dataclasses import dataclass

BASE = int(1e18)
# 15_768_000 is the number of blocks in a quarter
# estimated as 2 blocks per second
ONE_QUARTER_BLOCKS = 15_768_000

@pytest.fixture(scope="module")
def staking_control(cw3: Web3):
    return cw3.cfx.contract(name="Staking", with_deployment_info=True)


def get_new_account(cw3: Web3, value: int=1000 * BASE):
    account = cw3.cfx.account.create()
    cw3.wallet.add_account(account)
    cw3.cfx.send_transaction({
        "value": value,
        "to": account.address,
    }).executed()
    return account

@pytest.mark.parametrize(
    "locked_block,vote_power_factor",
    [
        (1 * ONE_QUARTER_BLOCKS, 0.25),
        (2 * ONE_QUARTER_BLOCKS, 0.5),
        (3 * ONE_QUARTER_BLOCKS, 0.5),
        (4 * ONE_QUARTER_BLOCKS, 1),
        (5 * ONE_QUARTER_BLOCKS, 1),
    ]
)
def test_vote_power(cw3: Web3, staking_control, locked_block: int, vote_power_factor):
    stake_amount = 100 * BASE
    account = get_new_account(cw3)
    staking_control.functions.deposit(stake_amount).transact({
        "from": account.address,
    }).executed()
    current_block_number = cw3.cfx.get_status()["blockNumber"]
    # 15_768_000 is the number of blocks in a quarter
    staking_control.functions.voteLock(
        stake_amount, current_block_number + locked_block + 10
    ).transact({
        "from": account.address,
    }).executed()
    
    votePower = staking_control.functions.getVotePower(account.address, current_block_number).call()
    assert votePower == stake_amount * vote_power_factor


def test_unlock(cw3: Web3, client, staking_control):
    stake_amount = 100 * BASE
    account = get_new_account(cw3)
    staking_control.functions.deposit(stake_amount).transact({
        "from": account.address,
    }).executed()
    current_block_number = cw3.cfx.get_status()["blockNumber"]
    unlock_block = 100 + current_block_number
    staking_control.functions.voteLock(
        stake_amount, unlock_block
    ).transact({
        "from": account.address,
    }).executed()
    
    assert staking_control.functions.getStakingBalance(account.address).call() == stake_amount
    assert staking_control.functions.getLockedStakingBalance(account.address, unlock_block-1).call() == stake_amount
    assert staking_control.functions.getLockedStakingBalance(account.address, unlock_block).call() == 0
    
    with pytest.raises(Web3RPCError) as e:
        staking_control.functions.withdraw(stake_amount).transact({
            "from": account.address,
        })

    assert e.value.rpc_response["error"]["message"] == 'Can not estimate: transaction execution failed, all gas will be charged (execution error: VmError(InternalContract("not enough withdrawable staking balance to withdraw")))'  # type: ignore
    assert e.value.rpc_response["error"]["code"] == -32015  # type: ignore
    assert e.value.rpc_response["error"]["data"] == 'VmError(InternalContract("not enough withdrawable staking balance to withdraw"))'  # type: ignore
    
    # wait for the lock block
    client.generate_blocks(5+unlock_block - cw3.cfx.get_status()["blockNumber"], num_txs=1)
    
    latest_state_block_number = cast(int, cw3.cfx.get_block_by_epoch_number("latest_state")["blockNumber"])
    assert latest_state_block_number >= unlock_block
    
    staking_control.functions.withdraw(stake_amount).transact({
        "from": account.address,
    }).executed()
    
    assert staking_control.functions.getStakingBalance(account.address).call() == 0
    assert staking_control.functions.getLockedStakingBalance(account.address, unlock_block).call() == 0


def test_stake_and_withdraw(cw3: Web3, staking_control):
    account = get_new_account(cw3)
    initial_balance = staking_control.functions.getStakingBalance(account.address).call()
    staking_control.functions.deposit(100 * BASE).transact({
        "from": account.address,
    }).executed()
    current_staking_balance = staking_control.functions.getStakingBalance(account.address).call()
    assert current_staking_balance - initial_balance == 100 * BASE
    
    staking_control.functions.withdraw(100 * BASE).transact({
        "from": account.address,
    }).executed()
    current_staking_balance = staking_control.functions.getStakingBalance(account.address).call()
    assert current_staking_balance == initial_balance

@dataclass
class VotePromise:
    amount: int
    unlock_block: int

def gen_all_vote_promises():
    amount_list = [100 * BASE, 200 * BASE, 300 * BASE, 400 * BASE]
    unlock_block_list = [
        ONE_QUARTER_BLOCKS,
        2 * ONE_QUARTER_BLOCKS,
        3 * ONE_QUARTER_BLOCKS,
        4 * ONE_QUARTER_BLOCKS,
    ]
    return [VotePromise(amount=amount, unlock_block=lock_block) for amount, lock_block in zip(amount_list, unlock_block_list)]

vote_promise_pool = gen_all_vote_promises()
# make 3 vote promises
all_combinations_with_duplicates = list(product(vote_promise_pool, repeat=3)) + list(product(vote_promise_pool, repeat=2))

sampled_combinations = random.sample(all_combinations_with_duplicates, 10)  # Sample subset

def should_lock_amount_at_block(vote_promises: list[VotePromise], block_number: int):
    locked_amount = 0
    for promise in vote_promises:
        if promise.unlock_block > block_number:
            locked_amount = max(locked_amount, promise.amount)
    return locked_amount

@pytest.mark.parametrize("vote_promises", sampled_combinations)
def test_multiple_vote_promises(cw3: Web3, staking_control, vote_promises: list[VotePromise]):
    account = get_new_account(cw3, 10000 * BASE)

    staking_control.functions.deposit(1000 * BASE).transact({
        "from": account.address,
    }).executed()
    
    for promise in vote_promises:
        staking_control.functions.voteLock(
            promise.amount, promise.unlock_block
        ).transact({
            "from": account.address,
        }).executed()
    
    for promise in vote_promises:
        should_lock = should_lock_amount_at_block(vote_promises, promise.unlock_block)
        assert staking_control.functions.getLockedStakingBalance(account.address, promise.unlock_block).call() == should_lock
