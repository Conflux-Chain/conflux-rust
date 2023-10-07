import os
from os.path import join, dirname, realpath
from produce_tx.account import build_account_map, reset_account_map
from produce_tx.transaction import dump_rpc_batches
import produce_tx.transfer as transfer
import produce_tx.erc20 as erc20
from produce_tx.sign import sign
import produce_tx.log as log
from produce_tx.contract import Contract
from produce_tx.params import *

DATA_PATH = join(dirname(realpath(__file__)), "../../experiment_data/transactions")


def complete_rest(tx_params, fout):
    log.debug("Assign nonce")
    for tx in tx_params:
        tx.assign_nonce()

    log.debug("Sign transactions")
    txs = sign(tx_params)

    log.debug("Encode and dump")
    dump_rpc_batches(txs, fout)


def generate_transfer(path, from_list, to_list, value=1, tx_num=None, chunk=500000, contract = None):
    reset_account_map()
    fout = open(path, "wb")

    log.notice("Make transactions")
    if contract is None:
        tx_params = transfer.make_transactions(from_list, to_list, value, tx_num)
    elif contract is not None:
        tx_params = erc20.make_transactions(from_list, to_list, value, contract, tx_num)
    else:
        raise Exception("unrecognized type")

    size = len(tx_params)
    for start in range(0, size, chunk):
        end = min(start + chunk, size)
        log.info(f"Process {start}/{size}")
        complete_rest(tx_params[start:end], fout)

    fout.close()
    log.notice("Done")


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
        generate_transfer(path(f"less_sender_{acc_num}"), range(LESS_SENDER), range(acc_num),
                          tx_num=RANDOM_TXS(acc_num), contract=contract)


def deploy_transfer():
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
    deploy_tx_param, erc20_contract = Contract.from_sol("erc20.sol", "FixedSupplyToken").deploy(0)
    txs = sign([deploy_tx_param])
    with open(join(folder_path, "deploy"), "wb") as fout:
        dump_rpc_batches(txs, fout)

    deploy_general_transfer(folder_path, contract=erc20_contract)


if __name__ == "__main__":
    log.set_level(0)

    # deploy_transfer()
    deploy_erc20()
