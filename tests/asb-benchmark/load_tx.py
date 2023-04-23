import os
import sys
import pickle

from utils import parse_num

from produce_tx import transaction

sys.modules['transaction'] = transaction

BASE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../..")
TRANSACTION_PATH = os.path.join(BASE_PATH, "experiment_data/transactions")

class LoadTask:
    def __init__(self, options):
        self.accounts_n = parse_num(options.keys)
        self.tx_n = parse_num(options.tx_num)
        self.warmup_n = parse_num(options.warmup_n)
        assert self.warmup_n == 0 or self.warmup_n > self.accounts_n

    def warmup_transaction(self):
        yield from []

    def bench_transaction(self):
        return []


class Native(LoadTask):
    def warmup_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"transfer/distribute")
        yield load(path, max(self.accounts_n, self.warmup_n))

    def bench_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"transfer/random_{self.accounts_n}")
        return load(path, self.tx_n)


class NativeLessSender(LoadTask):
    def warmup_transaction(self):
        if self.warmup_n > 20_000:
            path = os.path.join(TRANSACTION_PATH, f"transfer/distribute")
            yield load(path, self.warmup_n)

    def bench_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"transfer/less_sender_{self.accounts_n}")
        return load(path, self.tx_n)


class Erc20(LoadTask):
    def warmup_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"erc20/deploy")
        yield load(path, 1)

        path = os.path.join(TRANSACTION_PATH, f"erc20/distribute")
        yield load(path, max(self.accounts_n, self.warmup_n))

    def bench_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"erc20/random_{self.accounts_n}")
        return load(path, self.tx_n)


class Erc20LessSender(LoadTask):
    def warmup_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"erc20/deploy")
        yield load(path, 1)

        path = os.path.join(TRANSACTION_PATH, f"erc20/distribute")
        yield load(path, max(10_000, self.warmup_n))

    def bench_transaction(self):
        path = os.path.join(TRANSACTION_PATH, f"erc20/less_sender_{self.accounts_n}")
        return load(path, self.tx_n)


def load(path, tx_n):
    if tx_n == 0:
        return []

    if not os.path.isfile(path):
        raise Exception(f"File {path} does not exist")

    f = open(path, "rb")
    size = 0
    encoded_transactions = []
    while size < tx_n:
        encoded_transactions_batch = pickle.load(f)
        for rpc_batch in encoded_transactions_batch:
            size += rpc_batch.length
            encoded_transactions.append(rpc_batch)
            if size >= tx_n:
                break

    return encoded_transactions


def get_loader(options):
    if options.bench_token == "native":
        if options.bench_mode == "normal":
            loader = Native(options)
        elif options.bench_mode == "less-sender":
            loader = NativeLessSender(options)
        else:
            raise Exception("Unrecognized bench mode")
    elif options.bench_token == "erc20":
        if options.bench_mode == "normal":
            loader = Erc20(options)
        elif options.bench_mode == "less-sender":
            loader = Erc20LessSender(options)
        else:
            raise Exception("Unrecognized bench mode")
    else:
        raise Exception("Unrecognized bench token")

    return loader
