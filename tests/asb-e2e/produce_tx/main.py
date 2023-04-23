import accounts
import os
from accounts import build_account_map
from transaction import dump_rpc_batches
import transfer
import erc20
from sign import sign
from datetime import datetime
from params import *

BASE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../..")
log = lambda x: print(datetime.now().time(), x)

BALANCE = 1
ERC20 = 2


def complete_rest(tx_params, fout, **kwargs):
    log = kwargs.get("log", print)

    # log("Assign nonce")
    for tx in tx_params:
        tx.assign_nonce()

    # log("Sign")
    txs = sign(tx_params, log=log)

    # log("Encode and dump")
    dump_rpc_batches(txs, fout)


def generate_transfer(path, from_list, to_list, value=1, tx_num=None, chunk=500000, type=BALANCE, **kwargs):
    log = kwargs.get("log", print)

    accounts.reset_account_map(log=log)
    fout = open(path, "wb")

    log("Make transactions")
    if type == BALANCE:
        tx_params = transfer.make_transactions(from_list, to_list, value, tx_num)
    elif type == ERC20:
        tx_params = erc20.make_transactions(from_list, to_list, value, kwargs["contract"], tx_num)
    else:
        raise Exception("unrecognized type")

    size = len(tx_params)
    for start in range(0, size, chunk):
        end = min(start + chunk, size)
        log(f"Process {start}/{size}")
        complete_rest(tx_params[start:end], fout, log=log)

    fout.close()
    log("Done")


def deploy_general_transfer(type, folder_path, contract=None, **kwargs):
    log = kwargs.get("log", print)
    path = lambda x: os.path.join(folder_path, x)

    if type == BALANCE:
        init_range = 20000
    else:
        init_range = 1

    generate_transfer(path("distribute"), range(init_range), range(init_range, init_range + DISTRIBUTE_SIZE),
                      value=1_000_000_000_000_000_000,
                      type=type, contract=contract, log=log)

    # for acc_num in ACCOUNT_SIZE_LIST:
    #     log(f"Random for {acc_num}")
    #     generate_transfer(path(f"random_{acc_num}"), range(acc_num), range(acc_num),
    #                       type=type, tx_num=RANDOM_TXS, contract=contract, log=log)

    for acc_num in ACCOUNT_SIZE_LIST:
        log(f"Less sender for {acc_num}")
        generate_transfer(path(f"less_sender_{acc_num}"), range(LESS_SENDER), range(acc_num),
                          type=type, tx_num=RANDOM_TXS(acc_num), contract=contract, log=log)


def deploy_transfer():
    folder_path = os.path.join(BASE_PATH, f"experiment_data/transactions/transfer")
    os.makedirs(folder_path, exist_ok=True)

    init_range = 20_000
    max_number = max(DISTRIBUTE_SIZE, max(ACCOUNT_SIZE_LIST)) + init_range
    accounts.build_account_map(range(max_number), log=log)

    deploy_general_transfer(BALANCE, folder_path, log=log)


def deploy_erc20():
    folder_path = os.path.join(BASE_PATH, f"experiment_data/transactions/erc20")
    os.makedirs(folder_path, exist_ok=True)

    init_range = 1
    max_number = max(DISTRIBUTE_SIZE, max(ACCOUNT_SIZE_LIST)) + init_range
    accounts.build_account_map(range(max_number), log=log)

    deploy_param = erc20.make_contract(0)
    deploy_param.assign_nonce()
    contract_addr = deploy_param.contract_address()
    txs = sign([deploy_param])
    fout = open(os.path.join(folder_path, "deploy"), "wb")
    dump_rpc_batches(txs, fout)
    fout.close()

    deploy_general_transfer(ERC20, folder_path, contract=contract_addr, log=log)


if __name__ == "__main__":
    deploy_transfer()
    deploy_erc20()
