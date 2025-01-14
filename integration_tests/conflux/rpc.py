import os
import random
from typing import cast, Optional, Union, TypedDict, Any
from web3 import Web3

import eth_utils
from cfx_account import Account as CfxAccount
from eth_account.datastructures import SignedTransaction
import rlp
import json


from .address import hex_to_b32_address, b32_address_to_hex, DEFAULT_PY_TEST_CHAIN_ID
from .config import DEFAULT_PY_TEST_CHAIN_ID, default_config
from .transactions import CONTRACT_DEFAULT_GAS, Transaction, UnsignedTransaction
from .filter import Filter
from .utils import priv_to_addr, sha3_256, int_to_bytes, convert_to_nodeid, int_to_hex, encode_hex

import sys

sys.path.append("..")

from integration_tests.test_framework.util import (
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_is_hash_string,
    assert_is_hex_string,
    assert_equal,
    wait_until, checktx, get_contract_instance
)
from integration_tests.test_framework.test_node import TestNode

file_dir = os.path.dirname(os.path.realpath(__file__))
REQUEST_BASE = {
    'gas': CONTRACT_DEFAULT_GAS,
    'gasPrice': 1,
    'chainId': 1,
    "to": b'',
}

class CfxFeeHistoryResponse(TypedDict):
    baseFeePerGas: list[int]
    gasUsedRatio: list[float]
    reward: list[list[str]] # does not convert it currently


def convert_b32_address_field_to_hex(original_dict: dict, field_name: str):
    if original_dict is not None and field_name in original_dict and original_dict[field_name] not in [None, "null"]:
        original_dict[field_name] = b32_address_to_hex(original_dict[field_name])


class RpcClient:
    def __init__(self, node: Optional[TestNode]=None, auto_restart=False, log=None):
        self.node: TestNode = node # type: ignore
        self.auto_restart = auto_restart
        self.log = log

        # epoch definitions
        self.EPOCH_EARLIEST = "earliest"
        self.EPOCH_LATEST_MINED = "latest_mined"
        self.EPOCH_LATEST_STATE = "latest_state"
        self.EPOCH_LATEST_CONFIRMED = "latest_confirmed"

        # update node operations
        self.UPDATE_NODE_OP_FAILURE = "Failure"
        self.UPDATE_NODE_OP_DEMOTE = "Demotion"
        self.UPDATE_NODE_OP_REMOVE = "Remove"

        # hash/address definitions
        self.GENESIS_ADDR = eth_utils.encode_hex(priv_to_addr(default_config["GENESIS_PRI_KEY"]))
        self.GENESIS_PRI_KEY = default_config["GENESIS_PRI_KEY"]
        self.COINBASE_ADDR = eth_utils.encode_hex(default_config["GENESIS_COINBASE"])
        self.GENESIS_ORIGIN_COIN = default_config["TOTAL_COIN"]
        self.ZERO_HASH = eth_utils.encode_hex(b'\x00' * 32)

        # default tx values
        self.DEFAULT_TX_GAS_PRICE = 1
        self.DEFAULT_TX_GAS = 21000
        self.DEFAULT_TX_FEE = self.DEFAULT_TX_GAS_PRICE * self.DEFAULT_TX_GAS

    def EPOCH_NUM(self, num: int) -> str:
        return hex(num)

    def rand_addr(self) -> str:
        (addr, _) = self.rand_account()
        return addr

    def rand_account(self) -> (str, bytes):
        priv_key = eth_utils.encode_hex(os.urandom(32))
        addr = eth_utils.encode_hex(priv_to_addr(priv_key))
        return (Web3.to_checksum_address(addr), priv_key)

    def rand_hash(self, seed: bytes = None) -> str:
        if seed is None:
            seed = os.urandom(32)

        return eth_utils.encode_hex(sha3_256(seed))

    def generate_block(self, num_txs: int = 0,
                       block_size_limit_bytes: int = default_config["MAX_BLOCK_SIZE_IN_BYTES"]) -> str:
        assert_greater_than_or_equal(num_txs, 0)
        block_hash = self.node.test_generateOneBlock(num_txs, block_size_limit_bytes)
        assert_is_hash_string(block_hash)
        return block_hash

    def generate_blocks(self, num_blocks: int, num_txs: int = 0,
                        block_size_limit_bytes: int = default_config["MAX_BLOCK_SIZE_IN_BYTES"]) -> list:
        assert_greater_than(num_blocks, 0)
        assert_greater_than_or_equal(num_txs, 0)

        blocks = []
        for _ in range(0, num_blocks):
            block_hash = self.generate_block(num_txs, block_size_limit_bytes)
            blocks.append(block_hash)

        return blocks

    def generate_empty_blocks(self, num_blocks: int):
        return self.node.test_generateEmptyBlocks(num_blocks)

    def generate_blocks_to_state(self, num_blocks: int = 5, num_txs: int = 1) -> list:
        return self.generate_blocks(num_blocks, num_txs)

    def generate_block_with_parent(self, parent_hash: str, referee: list = None, num_txs: int = 0,
                                   adaptive: bool = False,
                                   difficulty=None, pos_reference=None) -> str:
        assert_is_hash_string(parent_hash)

        if referee is None:
            referee = []

        for r in referee:
            assert_is_hash_string(r)

        assert_greater_than_or_equal(num_txs, 0)
        # print(parent_hash)
        block_hash = self.node.test_generateFixedBlock(parent_hash, referee, num_txs, adaptive, difficulty, pos_reference)
        assert_is_hash_string(block_hash)
        return block_hash

    def generate_custom_block(self, parent_hash: str, referee: list, txs: list[Union[Transaction, SignedTransaction]]) -> str:
        assert_is_hash_string(parent_hash)

        for r in referee:
            assert_is_hash_string(r)

        raw_txs = []
        for tx in txs:
            if isinstance(tx, SignedTransaction):
                raw_txs.append(tx.raw_transaction)
            elif isinstance(tx, Transaction):
                raw_txs.append(rlp.encode(tx))
            else:
                raw_txs.append(rlp.encode(tx))
        
        encoded_txs = eth_utils.encode_hex(rlp.encode(raw_txs))

        block_hash = self.node.test_generateCustomBlock(parent_hash, referee, encoded_txs)
        assert_is_hash_string(block_hash)
        return block_hash

    def generate_block_with_fake_txs(self, txs: list, adaptive=False, tx_data_len: int = 0) -> str:
        encoded_txs = eth_utils.hexadecimal.encode_hex(rlp.encode(txs))
        block_hash = self.node.test_generateBlockWithFakeTxs(encoded_txs, adaptive, tx_data_len)
        assert_is_hash_string(block_hash)
        return block_hash

    def get_logs(self, filter: Filter) -> list:
        logs = self.node.cfx_getLogs(filter.__dict__)
        for log in logs:
            convert_b32_address_field_to_hex(log, "address")
        return logs

    def get_storage_at(self, addr: str, pos: str, epoch: str = None) -> str:
        assert_is_hash_string(addr, length=40)
        addr = hex_to_b32_address(addr)
        assert_is_hash_string(pos)

        if epoch is None:
            res = self.node.cfx_getStorageAt(addr, pos)
        else:
            res = self.node.cfx_getStorageAt(addr, pos, epoch)

        return res

    def get_storage_root(self, addr: str, epoch: str = None) -> str:
        assert_is_hash_string(addr, length=40)
        addr = hex_to_b32_address(addr)

        if epoch is None:
            res = self.node.cfx_getStorageRoot(addr)
        else:
            res = self.node.cfx_getStorageRoot(addr, epoch)

        return res

    def get_code(self, address: str, epoch: Union[str, dict] = None) -> str:
        address = hex_to_b32_address(address)
        if epoch is None:
            code = self.node.cfx_getCode(address)
        else:
            code = self.node.cfx_getCode(address, epoch)
        assert_is_hex_string(code)
        return code

    def gas_price(self) -> int:
        return int(self.node.cfx_gasPrice(), 0)

    def base_fee_per_gas(self, epoch: Union[int,str] = "latest_mined"):
        return int(self.block_by_epoch(epoch).get("baseFeePerGas", "0x0"), 16)

    def get_block_reward_info(self, epoch: str):
        reward = self.node.cfx_getBlockRewardInfo(epoch)
        convert_b32_address_field_to_hex(reward, "author")
        return reward

    def epoch_number(self, epoch: str = None) -> int:
        if epoch is None:
            return int(self.node.cfx_epochNumber(), 0)
        else:
            return int(self.node.cfx_epochNumber(epoch), 0)

    def get_balance(self, addr: str, epoch: str = None) -> int:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            return int(self.node.cfx_getBalance(addr), 0)
        else:
            return int(self.node.cfx_getBalance(addr, epoch), 0)

    def get_staking_balance(self, addr: str, epoch: str = None) -> int:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            return int(self.node.cfx_getStakingBalance(addr), 0)
        else:
            return int(self.node.cfx_getStakingBalance(addr, epoch), 0)

    def get_vote_list(self, addr: str, epoch: str = None) -> list:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            return self.node.cfx_getVoteList(addr)
        else:
            return self.node.cfx_getVoteList(addr, epoch)

    def get_deposit_list(self, addr: str, epoch: str = None) -> list:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            return self.node.cfx_getDepositList(addr)
        else:
            return self.node.cfx_getDepositList(addr, epoch)

    def get_collateral_for_storage(self, addr: str, epoch: str = None) -> int:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            return int(self.node.cfx_getCollateralForStorage(addr), 0)
        else:
            return int(self.node.cfx_getCollateralForStorage(addr, epoch), 0)

    def get_sponsor_info(self, addr: str, epoch: str = None) -> dict:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            r = self.node.cfx_getSponsorInfo(addr)
        else:
            r = self.node.cfx_getSponsorInfo(addr, epoch)
        convert_b32_address_field_to_hex(r, 'sponsorForGas')
        convert_b32_address_field_to_hex(r, 'sponsorForCollateral')
        return r

    def get_sponsor_for_gas(self, addr: str, epoch: str = None) -> str:
        return self.get_sponsor_info(addr, epoch)['sponsorForGas']

    def get_sponsor_for_collateral(self, addr: str, epoch: str = None) -> str:
        return self.get_sponsor_info(addr, epoch)['sponsorForCollateral']

    def get_sponsor_balance_for_collateral(self, addr: str, epoch: str = None) -> int:
        return int(self.get_sponsor_info(addr, epoch)['sponsorBalanceForCollateral'], 0)

    def get_sponsor_balance_for_gas(self, addr: str, epoch: str = None) -> int:
        return int(self.get_sponsor_info(addr, epoch)['sponsorBalanceForGas'], 0)

    def get_sponsor_gas_bound(self, addr: str, epoch: str = None) -> int:
        return int(self.get_sponsor_info(addr, epoch)['sponsorGasBound'], 0)
    
    def get_unused_storage_points(self, addr: str, epoch: str = None) -> int:
        return int(self.get_sponsor_info(addr, epoch)['availableStoragePoints'], 0)
    
    def get_used_storage_points(self, addr: str, epoch: str = None) -> int:
        return int(self.get_sponsor_info(addr, epoch)['usedStoragePoints'], 0)

    def get_admin(self, addr: str, epoch: str = None) -> str:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            r = self.node.cfx_getAdmin(addr)
        else:
            r = self.node.cfx_getAdmin(addr, epoch)
        return b32_address_to_hex(r)

    ''' Use the first but not None parameter and ignore the others '''

    def get_nonce(self, addr: str, epoch: str = None, block_hash: str = None, block_object: dict = None) -> int:
        addr = hex_to_b32_address(addr)
        if block_hash:
            block_hash = "hash:" + block_hash
        block_param = epoch or block_hash or block_object
        if block_param:
            return int(self.node.cfx_getNextNonce(addr, block_param), 0)
        else:
            return int(self.node.cfx_getNextNonce(addr), 0)

    def send_raw_tx(self, raw_tx: str, wait_for_catchup=True) -> str:
        # We wait for the node out of the catch up mode first
        if wait_for_catchup:
            self.node.wait_for_phase(["NormalSyncPhase"])
        tx_hash = self.node.cfx_sendRawTransaction(raw_tx)
        assert_is_hash_string(tx_hash)
        return tx_hash

    def clear_tx_pool(self):
        self.node.debug_clearTxPool()

    # a temporary patch for transaction compatibility
    def send_tx(self, tx: Union[Transaction, SignedTransaction], wait_for_receipt=False, wait_for_catchup=True) -> str:
        if isinstance(tx, SignedTransaction):
            encoded = cast(str, tx.raw_transaction.to_0x_hex())
        else:
            encoded = eth_utils.encode_hex(rlp.encode(tx))
        tx_hash = self.send_raw_tx(encoded, wait_for_catchup=wait_for_catchup)

        if wait_for_receipt:
            self.wait_for_receipt(tx_hash)

        return tx_hash

    def send_usable_genesis_accounts(self, account_start_index: int):
        self.node.test_sendUsableGenesisAccounts(account_start_index)

    def wait_for_receipt(self, tx_hash: str, num_txs=1, timeout=10, state_before_wait=True):
        if state_before_wait:
            self.generate_blocks_to_state(num_txs=num_txs)

        def check_tx():
            self.generate_block(num_txs)
            return checktx(self.node, tx_hash)

        try:
            wait_until(check_tx, timeout=timeout)
        except Exception as e:
            if self.log is not None:
                sender = self.node.cfx_getTransactionByHash(tx_hash)["from"]
                self.log.info("wait_for_receipt: pending=%s", self.node.cfx_getAccountPendingTransactions(sender))
            raise e

    def block_by_hash(self, block_hash: str, include_txs: bool = False) -> dict:
        block = self.node.cfx_getBlockByHash(block_hash, include_txs)
        convert_b32_address_field_to_hex(block, "miner")
        return block

    def block_by_hash_with_pivot_assumption(self, block_hash: str, pivot_hash: str, epoch: str) -> dict:
        block = self.node.cfx_getBlockByHashWithPivotAssumption(block_hash, pivot_hash, epoch)
        convert_b32_address_field_to_hex(block, "miner")
        return block

    def block_by_epoch(self, epoch: Union[str, int], include_txs: bool = False) -> dict:
        if type(epoch) is int:
            epoch = hex(epoch)

        block = self.node.cfx_getBlockByEpochNumber(epoch, include_txs)
        convert_b32_address_field_to_hex(block, "miner")
        return block

    def block_by_block_number(self, block_number: Union[str, int], include_txs: bool = False) -> dict:
        if type(block_number) is int:
            block_number = hex(block_number)

        block = self.node.cfx_getBlockByBlockNumber(block_number, include_txs)
        convert_b32_address_field_to_hex(block, "miner")
        return block

    def best_block_hash(self) -> str:
        return self.node.cfx_getBestBlockHash()

    def get_tx(self, tx_hash: str) -> dict:
        tx = self.node.cfx_getTransactionByHash(tx_hash)
        convert_b32_address_field_to_hex(tx, "from")
        convert_b32_address_field_to_hex(tx, "to")
        convert_b32_address_field_to_hex(tx, "contractCreated")
        return tx

    def new_tx(self, *, sender=None, receiver=None, nonce=None, gas_price=1, gas=21000, value=100, data=b'', sign=True,
               priv_key=None, storage_limit=None, epoch_height=None, chain_id=DEFAULT_PY_TEST_CHAIN_ID):
        if priv_key is None:
            priv_key = default_config["GENESIS_PRI_KEY"]
        if sender is None:
            sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        if receiver is None:
            receiver = self.COINBASE_ADDR

        if nonce is None:
            nonce = self.get_nonce(sender)

        if storage_limit is None:
            storage_limit = 0

        if epoch_height is None:
            epoch_height = self.epoch_number()

        action = eth_utils.hexadecimal.decode_hex(receiver)
        tx = UnsignedTransaction(nonce, gas_price, gas, action, value, data, storage_limit, epoch_height, chain_id)

        if sign:
            return tx.sign(priv_key)
        else:
            return tx
    
    def new_typed_tx(self, *, type_=2, receiver=None, nonce=None, max_fee_per_gas=None,max_priority_fee_per_gas=0, access_list=[], gas=21000, value=100, data=b'',
                    priv_key=None, storage_limit=0, epoch_height=None, chain_id=DEFAULT_PY_TEST_CHAIN_ID
    ) -> SignedTransaction:

        if priv_key:
            acct = CfxAccount.from_key(priv_key, DEFAULT_PY_TEST_CHAIN_ID)
        else:
            acct = CfxAccount.from_key(default_config["GENESIS_PRI_KEY"], DEFAULT_PY_TEST_CHAIN_ID)
        if receiver is None:
            receiver = self.COINBASE_ADDR
        tx = {}
        tx["type"] = type_
        tx["gas"] = gas
        tx["storageLimit"] = storage_limit
        tx["value"] = value
        tx["data"] = data
        tx["maxPriorityFeePerGas"] = max_priority_fee_per_gas
        tx["chainId"] = chain_id
        tx["to"] = receiver
            
        if nonce is None:
            nonce = self.get_nonce(acct.hex_address)
        tx["nonce"] = nonce

        if access_list != []:
            def format_access_list(a_list):
                rtn = []
                for item in a_list:
                    rtn.append({"address": item['address'], "storageKeys": item['storage_keys']})
        
            access_list = format_access_list(access_list)
        tx["accessList"] = access_list

        if epoch_height is None:
            epoch_height = self.epoch_number()
        tx["epochHeight"] = epoch_height
        
        # ensuring transaction can be sent
        if max_fee_per_gas is None:
            max_fee_per_gas = self.base_fee_per_gas('latest_mined') + 1
        tx["maxFeePerGas"] = max_fee_per_gas
        return acct.sign_transaction(tx)

    def new_contract_tx(self, receiver: Optional[str], data_hex: str = None, sender=None, priv_key=None, nonce=None,
                        gas_price=1,
                        gas=CONTRACT_DEFAULT_GAS, value=0, storage_limit=0, epoch_height=0,
                        chain_id=DEFAULT_PY_TEST_CHAIN_ID):
        if priv_key is None:
            priv_key = default_config["GENESIS_PRI_KEY"]
        elif priv_key == -1:
            priv_key = default_config["GENESIS_PRI_KEY_2"]

        if sender is None:
            sender = encode_hex(priv_to_addr(priv_key))

        if nonce is None:
            nonce = self.get_nonce(sender)
        elif type(nonce) is str:
            nonce = int(nonce, 0)

        if receiver is not None:
            action = eth_utils.hexadecimal.decode_hex(receiver)
        else:
            action = b''
        if data_hex is None:
            data_hex = "0x"
        data = eth_utils.hexadecimal.decode_hex(data_hex)

        if type(gas) is str:
            gas = int(gas, 0)

        if type(storage_limit) is str:
            storage_limit = int(storage_limit, 0)

        tx = UnsignedTransaction(nonce, gas_price, gas, action, value, data, storage_limit, epoch_height, chain_id)

        return tx.sign(priv_key)

    def block_hashes_by_epoch(self, epoch: str) -> list:
        blocks = self.node.cfx_getBlocksByEpoch(epoch)
        for b in blocks:
            assert_is_hash_string(b)
        return blocks

    def get_peers(self) -> list:
        return self.node.test_getPeerInfo()

    def get_peer(self, node_id: str):
        for p in self.get_peers():
            if p["nodeid"] == node_id:
                return p

        return None

    def get_node(self, node_id: str):
        return self.node.debug_getNetNode(node_id)

    def add_node(self, node_id: str, ip: str, port: int):
        self.node.test_addNode(node_id, "{}:{}".format(ip, port))

    def disconnect_peer(self, node_id: str, node_op: str = None) -> int:
        return self.node.debug_disconnectNetNode(node_id, node_op)

    def chain(self) -> list:
        return self.node.test_getChain()

    def get_transaction_receipt(self, tx_hash: str) -> dict[str, Any]:
        assert_is_hash_string(tx_hash)
        r = self.node.cfx_getTransactionReceipt(tx_hash)
        if r is None:
            return None
        
        convert_b32_address_field_to_hex(r, "contractCreated")
        convert_b32_address_field_to_hex(r, "from")
        convert_b32_address_field_to_hex(r, "to")

        if "storageCollateralized" in r:
            r["storageCollateralized"] = int(r["storageCollateralized"], 0)

        if "storageReleased" in r:
            storage_released = { b32_address_to_hex(item["address"]): int(item["collaterals"], 0) for item in r["storageReleased"] }
            r["storageReleased"] = storage_released
        return r

    def txpool_status(self) -> (int, int):
        status = self.node.txpool_status()
        return (eth_utils.to_int(hexstr=status["deferred"]), eth_utils.to_int(hexstr=status["ready"]))

    def new_tx_for_call(self, contract_addr: str = None, data_hex: str = None, nonce: int = None, sender: str = None):
        if sender is None:
            sender = self.GENESIS_ADDR
        if nonce is None:
            nonce = self.get_nonce(sender)
        if data_hex is None:
            data_hex = "0x"
        sender = hex_to_b32_address(sender)
        if contract_addr is not None:
            contract_addr = hex_to_b32_address(contract_addr)

        return {
            "hash": "0x" + "0" * 64,
            "nonce": hex(nonce),
            "from": sender,
            "to": contract_addr,
            "value": hex(0),
            "gasPrice": hex(1),
            "gas": hex(CONTRACT_DEFAULT_GAS),
            "data": data_hex,
            "v": hex(0),
            "r": hex(0),
            "s": hex(0),
        }

    def estimate_gas(self, contract_addr: str = None, data_hex: str = None, sender: str = None,
                     nonce: int = None) -> int:
        tx = self.new_tx_for_call(contract_addr, data_hex, sender=sender, nonce=nonce)
        response = self.node.cfx_estimateGasAndCollateral(tx)
        return int(response['gasUsed'], 0)

    def estimate_collateral(self, contract_addr: str = None, data_hex: str = None, sender: str = None,
                            nonce: int = None) -> int:
        tx = self.new_tx_for_call(contract_addr, data_hex, sender=sender, nonce=nonce)
        if contract_addr == "0x":
            del tx['to']
        if sender is None:
            del tx['from']
        response = self.node.cfx_estimateGasAndCollateral(tx)
        return response['storageCollateralized']

    def check_balance_against_transaction(self, account_addr: str, contract_addr: str, gas_limit: int, gas_price: int,
                                          storage_limit: int) -> dict:
        account_addr = hex_to_b32_address(account_addr)
        contract_addr = hex_to_b32_address(contract_addr)
        return self.node.cfx_checkBalanceAgainstTransaction(account_addr, contract_addr, hex(gas_limit), hex(gas_price),
                                                            hex(storage_limit))

    def call(self, contract_addr: str, data_hex: str, nonce=None, epoch: str = None, sender: str = None) -> str:
        tx = self.new_tx_for_call(contract_addr, data_hex, nonce=nonce, sender=sender)
        if epoch is None:
            return self.node.cfx_call(tx)
        else:
            return self.node.cfx_call(tx, epoch)

    def get_supply_info(self, epoch: str = None):
        if epoch is None:
            return self.node.cfx_getSupplyInfo()
        else:
            return self.node.cfx_getSupplyInfo(epoch)
        
    def get_collateral_info(self, epoch: str = None):
        if epoch is None:
            return self.node.cfx_getCollateralInfo()
        else:
            return self.node.cfx_getCollateralInfo(epoch)

    def get_params_from_vote(self, epoch: str = None):
        if epoch is None:
            return self.node.cfx_getParamsFromVote()
        else:
            return self.node.cfx_getParamsFromVote(epoch)

    def get_block_count(self):
        return self.node.test_getBlockCount()

    def get_account(self, addr: str, epoch: str = None):
        addr = hex_to_b32_address(addr)
        account = self.node.cfx_getAccount(addr, epoch)
        convert_b32_address_field_to_hex(account, "admin")
        return account

    def get_accumulate_interest_rate(self, epoch: str = None):
        return self.node.cfx_getAccumulateInterestRate(epoch)

    def get_interest_rate(self, epoch: str = None):
        return self.node.cfx_getInterestRate(epoch)

    def get_node_id(self):
        challenge = random.randint(0, 2 ** 32 - 1)
        signature = self.node.test_getNodeId(list(int_to_bytes(challenge)))
        node_id, _, _ = convert_to_nodeid(signature, challenge)
        return node_id

    def current_sync_phase(self):
        return self.node.debug_currentSyncPhase()

    def get_status(self):
        return self.node.cfx_getStatus()

    def get_block_trace(self, block_hash: str):
        return self.node.trace_block(block_hash)

    def get_transaction_trace(self, tx_hash: str):
        return self.node.trace_transaction(tx_hash)

    def filter_trace(self, filter: dict):
        return self.node.trace_filter(filter)
    
    def fee_history(self, epoch_count: int, last_epoch: Union[int, str], reward_percentiles: Optional[list[float]]=None) -> CfxFeeHistoryResponse:
        if reward_percentiles is None:
            reward_percentiles = [50]
        if isinstance(last_epoch, int):
            last_epoch = hex(last_epoch)
        rtn = self.node.cfx_feeHistory(hex(epoch_count), last_epoch, reward_percentiles)
        rtn[
            'baseFeePerGas'
        ] = [ int(v, 16) for v in rtn['baseFeePerGas'] ]
        return rtn


    def wait_for_pos_register(self, priv_key=None, stake_value=2_000_000, voting_power=None, legacy=True, should_fail=False):
        if priv_key is None:
            priv_key = self.node.pow_sk
        if voting_power is None:
            voting_power = stake_value // default_config["POS_VOTE_COUNT"]
        address = eth_utils.encode_hex(priv_to_addr(priv_key))
        initial_tx = self.new_tx(receiver=address, value=(stake_value + 20) * 10 ** 18)
        self.send_tx(initial_tx, wait_for_receipt=True)
        stake_tx = self.new_tx(priv_key=priv_key, data=stake_tx_data(stake_value), value=0,
                               receiver="0x0888000000000000000000000000000000000002", gas=CONTRACT_DEFAULT_GAS)
        self.send_tx(stake_tx, wait_for_receipt=True)
        data, pos_identifier = self.node.test_posRegister(int_to_hex(voting_power), 0 if legacy else 1)
        register_tx = self.new_tx(priv_key=priv_key, data=eth_utils.hexadecimal.decode_hex(data), value=0,
                                  receiver="0x0888000000000000000000000000000000000005", gas=CONTRACT_DEFAULT_GAS,
                                  storage_limit=1024)
        register_tx_hash = self.send_tx(register_tx, wait_for_receipt=True)
        assert_equal(
            int(self.node.cfx_getTransactionReceipt(register_tx_hash)["outcomeStatus"], 0),
            1 if should_fail else 0
        )
        return pos_identifier, priv_key

    def wait_for_unstake(self, priv_key=None, unstake_value=2_000_000):
        if priv_key is None:
            priv_key = self.node.pow_sk
        unstake_tx = self.new_tx(priv_key=priv_key, data=unstake_tx_data(unstake_value), value=0,
                                 receiver="0x0888000000000000000000000000000000000002", gas=CONTRACT_DEFAULT_GAS)
        self.send_tx(unstake_tx, wait_for_receipt=True)

    def pos_retire_self(self, unlock_vote: int):
        retire_tx = self.new_tx(priv_key=self.node.pow_sk, data=retire_tx_data(unlock_vote), value=0,
                                receiver="0x0888000000000000000000000000000000000005", gas=6_000_000)
        self.send_tx(retire_tx, wait_for_receipt=True)

    def pos_get_consensus_blocks(self):
        return self.node.pos_getConsensusBlocks()

    def pos_status(self):
        return self.node.pos_getStatus()

    def pos_get_block(self, block):
        if isinstance(block, str) and len(block) == 34:
            return self.node.pos_getBlockByHash(block)
        else:
            if isinstance(block, int):
                block = int_to_hex(block)
            return self.node.pos_getBlockByNumber(block)

    def pos_proposal_timeout(self):
        return self.node.test_posTriggerTimeout("proposal")

    def pos_local_timeout(self):
        return self.node.test_posTriggerTimeout("local")

    def pos_new_round_timeout(self):
        return self.node.test_posTriggerTimeout("new_round")

    def pos_force_sign_pivot_decision(self, block_hash, height):
        return self.node.test_posForceSignPivotDecision(block_hash, height)

    def pos_get_chosen_proposal(self):
        return self.node.test_posGetChosenProposal()

    def pos_get_account(self, account_address, view=None):
        if view is None:
            return self.node.pos_getAccount(account_address)
        else:
            return self.node.pos_getAccount(account_address, view)
    
    def pos_get_account_by_pow_address(self, address, view=None):
        address = hex_to_b32_address(address)
        if view is None:
            return self.node.pos_getAccountByPowAddress(address)
        else:
            return self.node.pos_getAccountByPowAddress(address, view)


def stake_tx_data(staking_value: int):
    staking_contract_dict = json.loads(
        open(os.path.join(file_dir, "../../internal_contract/metadata/Staking.json"), "r").read())
    staking_contract = get_contract_instance(contract_dict=staking_contract_dict)
    return get_contract_function_data(staking_contract, "deposit", args=[staking_value * 10 ** 18])


def unstake_tx_data(unstaking_value: int):
    staking_contract_dict = json.loads(
        open(os.path.join(file_dir, "../../internal_contract/metadata/Staking.json"), "r").read())
    staking_contract = get_contract_instance(contract_dict=staking_contract_dict)
    return get_contract_function_data(staking_contract, "withdraw", args=[unstaking_value * 10 ** 18])


def retire_tx_data(unlock_vote: int):
    register_contract_dict = json.loads(
        open(os.path.join(file_dir, "../../internal_contract/metadata/PoSRegister.json"), "r").read())
    register_contract = get_contract_instance(contract_dict=register_contract_dict)
    return get_contract_function_data(register_contract, "retire", args=[unlock_vote])


def lock_tx_data(locked_value: int, unlock_block_number: int):
    staking_contract_dict = json.loads(
        open(os.path.join(file_dir, "../../internal_contract/metadata/Staking.json"), "r").read())
    staking_contract = get_contract_instance(contract_dict=staking_contract_dict)
    return get_contract_function_data(staking_contract, "voteLock", args=[locked_value * 10 ** 18, unlock_block_number])


def get_contract_function_data(contract, name, args):
    func = getattr(contract.functions, name)
    attrs = {
        **REQUEST_BASE,
    }
    tx_data = func(*args).build_transaction(attrs)
    return eth_utils.hexadecimal.decode_hex(tx_data['data'])
