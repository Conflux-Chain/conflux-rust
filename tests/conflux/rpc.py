import os
import random

import eth_utils
import rlp

from .address import hex_to_b32_address, b32_address_to_hex
from .config import DEFAULT_PY_TEST_CHAIN_ID, default_config
from .transactions import CONTRACT_DEFAULT_GAS, Transaction, UnsignedTransaction
from .filter import Filter
from .utils import priv_to_addr, sha3_256, int_to_bytes, convert_to_nodeid

import sys
sys.path.append("..")

from test_framework.util import (
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_is_hash_string,
    assert_is_hex_string,
    wait_until, checktx
)


def convert_b32_address_field_to_hex(original_dict: dict, field_name: str):
    if field_name in original_dict and original_dict[field_name] != "null":
        original_dict[field_name] = b32_address_to_hex(original_dict[field_name])


class RpcClient:
    def __init__(self, node=None, auto_restart=False):
        self.node = node
        self.auto_restart = auto_restart

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
        return (addr, priv_key)

    def rand_hash(self, seed: bytes = None) -> str:
        if seed is None:
            seed = os.urandom(32)
        
        return eth_utils.encode_hex(sha3_256(seed))

    def generate_block(self, num_txs: int = 0,
                       block_size_limit_bytes: int = default_config["MAX_BLOCK_SIZE_IN_BYTES"]) -> str:
        assert_greater_than_or_equal(num_txs, 0)
        block_hash = self.node.generateoneblock(num_txs, block_size_limit_bytes)
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
        return self.node.generate_empty_blocks(num_blocks)

    def generate_blocks_to_state(self, num_blocks: int = 5, num_txs: int = 1) -> list:
        return self.generate_blocks(num_blocks, num_txs)

    def generate_block_with_parent(self, parent_hash: str, referee: list = [], num_txs: int = 0, adaptive: bool = False) -> str:
        assert_is_hash_string(parent_hash)

        for r in referee:
            assert_is_hash_string(r)

        assert_greater_than_or_equal(num_txs, 0)
        # print(parent_hash)
        block_hash = self.node.generatefixedblock(parent_hash, referee, num_txs, adaptive)
        assert_is_hash_string(block_hash)
        return block_hash

    def generate_custom_block(self, parent_hash: str, referee: list, txs: list) -> str:
        assert_is_hash_string(parent_hash)

        for r in referee:
            assert_is_hash_string(r)

        encoded_txs = eth_utils.encode_hex(rlp.encode(txs))

        block_hash = self.node.test_generatecustomblock(parent_hash, referee, encoded_txs)
        assert_is_hash_string(block_hash)
        return block_hash

    def generate_block_with_fake_txs(self, txs: list, adaptive=False, tx_data_len: int = 0) -> str:
        encoded_txs = eth_utils.encode_hex(rlp.encode(txs))
        block_hash = self.node.test_generateblockwithfaketxs(encoded_txs, adaptive, tx_data_len)
        assert_is_hash_string(block_hash)
        return block_hash

    def get_logs(self, filter: Filter) -> list:
        logs = self.node.cfx_getLogs(filter.__dict__)
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

    def get_code(self, address: str, epoch: str = None) -> str:
        address = hex_to_b32_address(address)
        if epoch is None:
            code = self.node.cfx_getCode(address)
        else:
            code = self.node.cfx_getCode(address, epoch)
        assert_is_hex_string(code)
        return code

    def gas_price(self) -> int:
        return int(self.node.cfx_gasPrice(), 0)

    def get_block_reward_info(self, epoch: str):
        reward = self.node.cfx_getBlockRewardInfo(epoch)
        convert_b32_address_field_to_hex(reward, "author")

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
            return self.node.cfx_getSponsorInfo(addr)
        else:
            return self.node.cfx_getSponsorInfo(addr, epoch)

    def get_sponsor_for_gas(self, addr: str, epoch: str = None) -> str:
        addr = hex_to_b32_address(addr)
        return self.get_sponsor_info(addr, epoch)['sponsorForGas']

    def get_sponsor_for_collateral(self, addr: str, epoch: str = None) -> str:
        addr = hex_to_b32_address(addr)
        return self.get_sponsor_info(addr, epoch)['sponsorForCollateral']

    def get_sponsor_balance_for_collateral(self, addr: str, epoch: str = None) -> int:
        return int(self.get_sponsor_info(addr, epoch)['sponsorBalanceForCollateral'], 0)

    def get_sponsor_balance_for_gas(self, addr: str, epoch: str = None) -> int:
        addr = hex_to_b32_address(addr)
        return int(self.get_sponsor_info(addr, epoch)['sponsorBalanceForGas'], 0)

    def get_sponsor_gas_bound(self, addr: str, epoch: str = None) -> int:
        addr = hex_to_b32_address(addr)
        return int(self.get_sponsor_info(addr, epoch)['sponsorGasBound'], 0)

    def get_admin(self, addr: str, epoch: str = None) -> str:
        addr = hex_to_b32_address(addr)
        if epoch is None:
            return self.node.cfx_getAdmin(addr)
        else:
            return self.node.cfx_getAdmin(addr, epoch)

    ''' Ignore block_hash if epoch is not None '''
    def get_nonce(self, addr: str, epoch: str = None, block_hash: str = None) -> int:
        addr = hex_to_b32_address(addr)
        if epoch is None and block_hash is None:
            return int(self.node.cfx_getNextNonce(addr), 0)
        elif epoch is None:
            return int(self.node.cfx_getNextNonce(addr, "hash:"+block_hash), 0)
        else:
            return int(self.node.cfx_getNextNonce(addr, epoch), 0)

    def send_raw_tx(self, raw_tx: str, wait_for_catchup=True) -> str:
        # We wait for the node out of the catch up mode first
        if wait_for_catchup:
            self.node.wait_for_phase(["NormalSyncPhase"])
        tx_hash = self.node.cfx_sendRawTransaction(raw_tx)
        assert_is_hash_string(tx_hash)
        return tx_hash

    def clear_tx_pool(self):
        self.node.clear_tx_pool()


    def send_tx(self, tx: Transaction, wait_for_receipt=False, wait_for_catchup=True) -> str:
        encoded = eth_utils.encode_hex(rlp.encode(tx))
        tx_hash = self.send_raw_tx(encoded, wait_for_catchup=wait_for_catchup)
        
        if wait_for_receipt:
            self.wait_for_receipt(tx_hash)
        
        return tx_hash

    def send_usable_genesis_accounts(self, account_start_index:int):
        self.node.test_sendUsableGenesisAccounts(account_start_index)

    def wait_for_receipt(self, tx_hash: str, num_txs=1, timeout=10, state_before_wait=True):
        if state_before_wait:
            self.generate_blocks_to_state(num_txs=num_txs)
        
        def check_tx():
            self.generate_block(num_txs)
            return checktx(self.node, tx_hash)
        wait_until(check_tx, timeout=timeout)

    def block_by_hash(self, block_hash: str, include_txs: bool = False) -> dict:
        block = self.node.cfx_getBlockByHash(block_hash, include_txs)
        convert_b32_address_field_to_hex(block, "miner")
        return block

    def block_by_epoch(self, epoch: str, include_txs: bool = False) -> dict:
        block = self.node.cfx_getBlockByEpochNumber(epoch, include_txs)
        convert_b32_address_field_to_hex(block, "miner")
        return block

    def best_block_hash(self) -> str:
        return self.node.cfx_getBestBlockHash()

    def get_tx(self, tx_hash: str) -> dict:
        return self.node.cfx_getTransactionByHash(tx_hash)

    def new_tx(self, sender = None, receiver = None, nonce = None, gas_price=1, gas=21000, value=100, data=b'', sign=True, priv_key=None, storage_limit=None, epoch_height=0, chain_id=DEFAULT_PY_TEST_CHAIN_ID):
        if sender is None:
            sender = self.GENESIS_ADDR
            if priv_key is None:
                priv_key = default_config["GENESIS_PRI_KEY"]

        if receiver is None:
            receiver = self.COINBASE_ADDR
        
        if nonce is None:
            nonce = self.get_nonce(sender)

        if storage_limit is None:
            storage_limit = 0

        action = eth_utils.decode_hex(receiver)
        tx = UnsignedTransaction(nonce, gas_price, gas, action, value, data, storage_limit, epoch_height, chain_id)
        
        if sign:
            return tx.sign(priv_key)
        else:
            return tx

    def new_contract_tx(self, receiver:str, data_hex:str, sender=None, priv_key=None, nonce=None, gas_price=1, gas=CONTRACT_DEFAULT_GAS, value=0, storage_limit=0, epoch_height=0, chain_id=DEFAULT_PY_TEST_CHAIN_ID):
        if sender is None:
            sender = self.GENESIS_ADDR

        if priv_key is None:
            priv_key = default_config["GENESIS_PRI_KEY"]

        if nonce is None:
            nonce = self.get_nonce(sender)

        action = eth_utils.decode_hex(receiver)
        data = eth_utils.decode_hex(data_hex)
        tx = UnsignedTransaction(nonce, gas_price, gas, action, value, data, storage_limit, epoch_height, chain_id)

        return tx.sign(priv_key)

    def block_hashes_by_epoch(self, epoch: str) -> list:
        blocks = self.node.cfx_getBlocksByEpoch(epoch)
        for b in blocks:
            assert_is_hash_string(b)
        return blocks

    def get_peers(self) -> list:
        return self.node.getpeerinfo()

    def get_peer(self, node_id: str):
        for p in self.get_peers():
            if p["nodeid"] == node_id:
                return p

        return None

    def get_node(self, node_id: str):
        return self.node.net_node(node_id)

    def add_node(self, node_id: str, ip: str, port: int):
        self.node.addnode(node_id, "{}:{}".format(ip, port))

    def disconnect_peer(self, node_id: str, node_op:str=None) -> int:
        return self.node.net_disconnect_node(node_id, node_op)

    def chain(self) -> list:
        return self.node.cfx_getChain()

    def get_transaction_receipt(self, tx_hash: str) -> dict:
        assert_is_hash_string(tx_hash)
        r = self.node.cfx_getTransactionReceipt(tx_hash)
        convert_b32_address_field_to_hex(r, "contractCreated")

    def txpool_status(self) -> (int, int):
        status = self.node.txpool_status()
        return (status["deferred"], status["ready"])

    def new_tx_for_call(self, contract_addr:str, data_hex:str, nonce:int=None, sender:str=None):
        if sender is None:
            sender = self.GENESIS_ADDR
        if nonce is None:
            nonce = self.get_nonce(sender)
        sender = hex_to_b32_address(sender)
        contract_addr = hex_to_b32_address(contract_addr)

        return {
            "hash": "0x"+"0"*64,
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

    def estimate_gas(self, contract_addr:str, data_hex:str, sender:str=None, nonce:int=None) -> int:
        tx = self.new_tx_for_call(contract_addr, data_hex, sender=sender, nonce=nonce)
        response = self.node.cfx_estimateGasAndCollateral(tx)
        return int(response['gasUsed'], 0)

    def estimate_collateral(self, contract_addr:str, data_hex:str, sender:str=None, nonce:int=None) -> int:
        tx = self.new_tx_for_call(contract_addr, data_hex, sender=sender, nonce=nonce)
        if contract_addr == "0x":
            del tx['to']
        if sender is None:
            del tx['from']
        response = self.node.cfx_estimateGasAndCollateral(tx)
        return response['storageCollateralized']

    def check_balance_against_transaction(self, account_addr: str, contract_addr: str, gas_limit: int, gas_price: int, storage_limit: int) -> dict:
        account_addr = hex_to_b32_address(account_addr)
        contract_addr = hex_to_b32_address(contract_addr)
        return self.node.cfx_checkBalanceAgainstTransaction(account_addr, contract_addr, hex(gas_limit), hex(gas_price), hex(storage_limit))

    def call(self, contract_addr:str, data_hex:str, nonce=None, epoch:str=None) -> str:
        tx = self.new_tx_for_call(contract_addr, data_hex, nonce=nonce)
        if epoch is None:
            return self.node.cfx_call(tx)
        else:
            return self.node.cfx_call(tx, epoch)

    def get_supply_info(self, epoch:str=None):
        if epoch is None:
            return self.node.cfx_getSupplyInfo()
        else:
            return self.node.cfx_getSupplyInfo(epoch)

    def get_block_count(self):
        return self.node.getblockcount()

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
        challenge = random.randint(0, 2**32-1)
        signature = self.node.getnodeid(list(int_to_bytes(challenge)))
        node_id, _, _ = convert_to_nodeid(signature, challenge)
        return node_id

    def get_transaction_by_hash(self, tx_hash: str):
        tx = self.node.cfx_getTransactionByHash(tx_hash)
        convert_b32_address_field_to_hex(tx, "from")
        convert_b32_address_field_to_hex(tx, "to")
        convert_b32_address_field_to_hex(tx, "contractCreated")
        return tx
