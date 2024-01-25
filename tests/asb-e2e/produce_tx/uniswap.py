import os
from os.path import join, dirname, realpath

from .account import build_account_map, record_account_map, recover_account_map, get_account_address
from .transaction import dump_rpc_batches, TxParam
from .calldata_template import address_ph
from .sign import sign
from . import log
from .contract import Contract
from .params import *
from .transfer import generate_transfer, sign_encode_dump_txs_in_batch
from .native import faucet_balance
import sha3
import random
from web3 import Web3
from typing import List

DATA_PATH = join(dirname(realpath(__file__)), "../../../experiment_data/transactions")


def make_approve_transactions(sender_list, spender, contracts: List[Contract]) -> List[TxParam]:
    answers = []
    sender_list = list(sender_list)
    batch_size = RLP_BATCH_SIZE

    assert len(sender_list) % batch_size == 0, "List length must be a multiple of batch_size"
    templates = [contract.build_template("approve", spender, 2**256 - 1) for contract in contracts]

    for sender_batch in [sender_list[i:i+batch_size] for i in range(0, len(sender_list), batch_size)]:
        for template in templates:
            for sender_index in sender_batch:
                answers.append(template.build_tx_param(sender_index))

    return answers

def make_swap_transactions(sender_list, token_a_address, token_b_address, router_contracts, tx_n, swap_eth = False) -> List[TxParam]:
    SWAP_BASE = 10 ** 16
    sender_list = list(sender_list)
    log.info("Random pick swap task")
    tasks = [(random.choice(sender_list), random.randint(0, 3)) for _ in range(tx_n)]

    templates = []

    if not swap_eth:
        templates.append(router_contracts.build_template("swapExactTokensForTokens", SWAP_BASE, int(SWAP_BASE / 2), [token_a_address, token_b_address], address_ph(0), 2**60))
        templates.append(router_contracts.build_template("swapExactTokensForTokens", SWAP_BASE, int(SWAP_BASE / 2), [token_b_address, token_a_address], address_ph(0), 2**60))
        templates.append(router_contracts.build_template("swapTokensForExactTokens", SWAP_BASE, SWAP_BASE * 2, [token_a_address, token_b_address], address_ph(0), 2**60))
        templates.append(router_contracts.build_template("swapTokensForExactTokens", SWAP_BASE, SWAP_BASE * 2, [token_b_address, token_a_address], address_ph(0), 2**60))
    else:
        templates.append(router_contracts.build_template("swapExactTokensForETH", SWAP_BASE, int(SWAP_BASE / 2), [token_a_address, token_b_address], address_ph(0), 2**60))
        templates.append(router_contracts.build_template_with_value("swapExactETHForTokens", SWAP_BASE, int(SWAP_BASE / 2), [token_b_address, token_a_address], address_ph(0), 2**60))
        templates.append(router_contracts.build_template("swapTokensForExactETH", SWAP_BASE, SWAP_BASE * 2, [token_a_address, token_b_address], address_ph(0), 2**60))
        templates.append(router_contracts.build_template_with_value("swapETHForExactTokens", SWAP_BASE * 2, SWAP_BASE,  [token_b_address, token_a_address], address_ph(0), 2**60))
    log.info("Construct calldata")
    return [templates[i].build_tx_param(sender_index, get_account_address(sender_index)) for (sender_index, i) in tasks]

def deploy():
    folder_path = join(DATA_PATH, f"uniswap")
    os.makedirs(folder_path, exist_ok=True)

    reserve_range = 10
    max_number = max(DISTRIBUTE_SIZE, max(ACCOUNT_SIZE_LIST)) + reserve_range

    build_account_map(range(max_number))

    ##########################
    # Step 1: Deploy contracts
    ##########################

    # 1a. deploy tokenA
    token_a_deploy, token_a_contract = Contract.from_artifacts("FixedSupplyToken").deploy(1)
    token_a_deploy.set_tag("Deploy token A")

    # 1b. deploy tokenB
    token_b_deploy, token_b_contract = Contract.from_artifacts("FixedSupplyToken").deploy(2)
    token_b_deploy.set_tag("Deploy token B")

    # 1c. deploy WETH 
    weth_deploy, weth_contract = Contract.from_artifacts("WETH").deploy(3)
    weth_deploy.set_tag("Deploy token WETH")

    # 1d. deploy uniswap factory
    factory_deploy, factory_contract = Contract.from_artifacts("UniswapV2Factory").deploy(0, get_account_address(0))
    factory_deploy.set_tag("Deploy Uniswap Factory")

    log.warn("Factory address", factory_contract.address)
    log.warn("Token A Address", token_a_contract.address)
    log.warn("Token B Address", token_b_contract.address)
    log.warn("WETH Address", weth_contract.address)
        
    with open(join(folder_path, "deploy_1"), "wb") as fout:
        txs = sign([token_a_deploy, token_b_deploy, weth_deploy, factory_deploy])
        dump_rpc_batches(txs, fout)

    ##########################
    # Step 2: Deploy contracts
    ##########################

    # 2a. deploy uniswap pair
    pair_deploy = factory_contract.call(0, "createPair", token_a_contract.address, token_b_contract.address)
    pair_deploy.set_tag("Pair deploy")
    deploy_size = int(len(Contract.from_artifacts("UniswapV2Pair").contract.bytecode) * 1.2)
    log.warn("Deploy size", deploy_size)
    pair_bytecode_hash()
    pair_deploy.set_gas(gas = 13_000_000, storage_limit = deploy_size)

    eth_pair_deploy = factory_contract.call(0, "createPair", token_a_contract.address, weth_contract.address)
    eth_pair_deploy.set_tag("ETH Pair deploy")
    deploy_size = int(len(Contract.from_artifacts("UniswapV2Pair").contract.bytecode) * 1.2)
    log.warn("Deploy size", deploy_size)
    pair_bytecode_hash()
    eth_pair_deploy.set_gas(gas = 13_000_000, storage_limit = deploy_size)

    # 2b. deploy uniswap router
    router_deploy, router_contract = Contract.from_artifacts("UniswapV2Router02").deploy(3, factory_contract.address, weth_contract.address)
    router_deploy.set_tag("Router deploy")

    # 2b. add liquidity
    send_token_a = token_a_contract.call(1, "transfer", get_account_address(3), 2 * 10 ** 6 * 10 ** 18)
    send_token_b = token_b_contract.call(2, "transfer", get_account_address(3), 10 ** 6 * 10 ** 18)
    faucet_token = faucet_balance(3, 10 ** 6)

    with open(join(folder_path, "deploy_2"), "wb") as fout:
        txs = sign([pair_deploy, eth_pair_deploy, router_deploy, send_token_a, send_token_b, faucet_token])
        dump_rpc_batches(txs, fout)

    ##########################
    # Step 3: Add liquidity
    ##########################
    approve_token_a = token_a_contract.call(3, "approve", router_contract.address, 2**256 - 1)
    approve_token_b = token_b_contract.call(3, "approve", router_contract.address, 2**256 - 1)
    add_liquidity = router_contract.call(3, "addLiquidity", token_a_contract.address, token_b_contract.address, 10 ** 6 * 10 ** 18, 10 ** 6 * 10 ** 18, 0, 0, get_account_address(3), 2**60)
    add_liquidity.set_tag("Add liquidity for token pool")
    add_liquidity_eth = router_contract.call_with_value(3, "addLiquidityETH", 10 ** 6 * 10 ** 18, token_a_contract.address, 10 ** 6 * 10 ** 18, 0, 0, get_account_address(3), 2**60) 
    add_liquidity_eth.set_tag("Add liquidity for ETH pool")


    with open(join(folder_path, "add_liquidity"), "wb") as fout:
        txs = sign([approve_token_a, approve_token_b, add_liquidity, add_liquidity_eth])
        for tx in txs:
            dump_rpc_batches([tx], fout)

    ###########################################
    # Step 4: Distribute and approve token and 
    ###########################################

    path = lambda x: join(folder_path, x)

    # 4a. distribute tokenA
    log.notice("Distribute token A")
    generate_transfer(path("distribute_token_a"), [1], range(reserve_range, reserve_range + DISTRIBUTE_SIZE), value=10**18, contract=token_a_contract)
    # 4b. distribute tokenB
    log.notice("Distribute token B")
    generate_transfer(path("distribute_token_b"), [2], range(reserve_range, reserve_range + DISTRIBUTE_SIZE), value=10**18, contract=token_b_contract)
    # 4c. distribute Native
    log.notice("Distribute native token")
    generate_transfer(path("distribute_native"), ["genesis"], range(reserve_range, reserve_range + DISTRIBUTE_SIZE), value=5 * 10**18)
    # 4d. approve tokens
    log.notice("Approve tokens")
    txs = make_approve_transactions(range(reserve_range, reserve_range + DISTRIBUTE_SIZE), router_contract.address, [token_a_contract, token_b_contract])
    sign_encode_dump_txs_in_batch(path("approval"), txs)

    ###########################################
    # Step 5: Swap tasks
    ###########################################

    record_account_map("swap")
    for acc_num in ACCOUNT_SIZE_LIST:
        log.notice(f"Swap token for {acc_num}")
        recover_account_map("swap")
        txs = make_swap_transactions(range(reserve_range, reserve_range + acc_num), token_a_contract.address, token_b_contract.address, router_contract, SWAP_TXS(acc_num) )
        sign_encode_dump_txs_in_batch(path(f"swap_token_{acc_num}"), txs)

    for acc_num in ACCOUNT_SIZE_LIST:
        log.notice(f"Swap eth for {acc_num}")
        recover_account_map("swap")
        txs = make_swap_transactions(range(reserve_range, reserve_range + acc_num), token_a_contract.address, weth_contract.address, router_contract, SWAP_TXS(acc_num), swap_eth = True )
        sign_encode_dump_txs_in_batch(path(f"swap_eth_{acc_num}"), txs)


def pair_bytecode_hash():
    bytecode_hash = sha3.keccak_256(Contract.from_artifacts("UniswapV2Pair").contract.bytecode).digest()
    log.critical(bytecode_hash.hex())

# def uniswap_v2_pair_address(factory: str, token_a: str, token_b: str):
#     factory = bytes.fromhex(factory[2:].lower())
#     token_a = bytes.fromhex(token_a[2:].lower())
#     token_b = bytes.fromhex(token_b[2:].lower())
#     if token_a > token_b:
#         token_a, token_b = token_b, token_a

#     salt = sha3.keccak_256(token_a + token_b).digest()
#     bytecode_hash = sha3.keccak_256(Contract.from_artifacts("UniswapV2Pair").contract.bytecode).digest()
#     eth_address = sha3.keccak_256(b'\xff' + factory + salt + bytecode_hash).digest()[12:]
#     cfx_address = (eth_address[0] & 0x0f | 0x80).to_bytes(1, "big") + eth_address[1:]
#     pair_address = Web3.toChecksumAddress("0x" + cfx_address.hex())


#     log.critical("Bytecode hash", bytecode_hash.hex())
#     log.warn("Predict Uniswap pair address", pair_address)
#     return pair_address