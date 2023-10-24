import os
from os.path import join, dirname, realpath

from .account import build_account_map, reset_account_map
from .transaction import dump_rpc_batches
from . import native
from . import erc20
from .sign import sign
from . import log
from .contract import Contract
from .params import *

DATA_PATH = join(dirname(realpath(__file__)), "../../../experiment_data/transactions")


def complete_rest(tx_params, fout):
    log.debug("Assign nonce")
    for tx in tx_params:
        tx.assign_nonce()

    log.debug("Sign transactions")
    txs = sign(tx_params)

    log.debug("Encode and dump")
    dump_rpc_batches(txs, fout)


def generate_transfer(path, from_list, to_list, value=1, tx_num=None, chunk=500000, contract = None):
    log.info("Make transfer transactions")
    if contract is None:
        tx_params = native.make_transactions(from_list, to_list, value, tx_num)
    elif contract is not None:
        tx_params = erc20.make_transactions(from_list, to_list, value, contract, tx_num)
    else:
        raise Exception("unrecognized type")
    sign_encode_dump_txs_in_batch(path, tx_params, chunk)


def sign_encode_dump_txs_in_batch(path, tx_params, chunk=500000):
    fout = open(path, "wb")

    size = len(tx_params)
    for start in range(0, size, chunk):
        end = min(start + chunk, size)
        log.info(f"Sign & Encode & Dump {start}/{size}")
        complete_rest(tx_params[start:end], fout)

    fout.close()
    log.info(f"Sign & Encode & Dump {size}/{size}")

def deploy_general_transfer(folder_path, contract=None):
    path = lambda x: join(folder_path, x)

    if contract is None:
        inited_account_num = 20000
    else:
        inited_account_num = 1

    generate_transfer(path("distribute"), range(inited_account_num), range(inited_account_num, inited_account_num + DISTRIBUTE_SIZE),
                      value=1_000_000_000_000_000_000,
                      contract=contract)

    # for acc_num in ACCOUNT_SIZE_LIST:
    #     log.notice(f"Random for {acc_num}")
    #     generate_transfer(path(f"random_{acc_num}"), range(acc_num), range(acc_num),
    #                       tx_num=RANDOM_TXS, contract=contract)

    for acc_num in ACCOUNT_SIZE_LIST:
        log.notice(f"Less sender for {acc_num}")
        reset_account_map()
        generate_transfer(path(f"less_sender_{acc_num}"), range(LESS_SENDER), range(acc_num),
                          tx_num=RANDOM_TXS(acc_num), contract=contract)


def deploy_native():
    folder_path = join(DATA_PATH, f"transfer")
    os.makedirs(folder_path, exist_ok=True)

    init_range = 20_000
    max_number = max(DISTRIBUTE_SIZE, max(ACCOUNT_SIZE_LIST)) + init_range
    build_account_map(range(max_number))

    deploy_general_transfer(folder_path)


def deploy_erc20():
    folder_path = join(DATA_PATH, f"erc20")
    os.makedirs(folder_path, exist_ok=True)

    init_range = 1
    max_number = max(DISTRIBUTE_SIZE, max(ACCOUNT_SIZE_LIST)) + init_range
    # max_number = 100
    build_account_map(range(max_number))

    log.notice("Deploy contract")
    # deploy_tx_param, erc20_contract = Contract.from_sol("erc20.sol", "FixedSupplyToken").deploy(0)
    deploy_tx_param, erc20_contract = Contract.from_artifacts("FixedSupplyToken").deploy(0)
    txs = sign([deploy_tx_param])
    with open(join(folder_path, "deploy"), "wb") as fout:
        dump_rpc_batches(txs, fout)

    deploy_general_transfer(folder_path, contract=erc20_contract)