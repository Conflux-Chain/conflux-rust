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


def load(path, tx_n = None):
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


class Uniswap(LoadTask):
    def warmup_transaction(self):
        path = lambda x: os.path.join(TRANSACTION_PATH, f"uniswap/{x}")
        print("warmup uniswap erc20")

        print("Deploy contract group 1")
        yield load(path("deploy_1"), 4)

        print("Deploy contract group 2")
        yield load(path("deploy_2"), 6)

        for tx in load(path("add_liquidity"), 4):
            print("Add liquidity in step")
            yield [tx]
        
        print("Distribute toke A")
        yield load(path("distribute_token_a"), self.accounts_n)
        print("Distribute toke B")
        yield load(path("distribute_token_b"), self.accounts_n)
        print("Distribute native")
        yield load(path("distribute_native"), self.accounts_n)
        print("Approval")
        yield load(path("approval"), self.accounts_n * 2)

    def bench_transaction(self):
        path = lambda x: os.path.join(TRANSACTION_PATH, f"uniswap/{x}")
        return load(path(f"swap_token_{self.accounts_n}"), self.tx_n)

class UniswapETH(LoadTask):
    def warmup_transaction(self):
        path = lambda x: os.path.join(TRANSACTION_PATH, f"uniswap/{x}")
        print("warmup uniswap eth")

        print("Deploy contract group 1")
        yield load(path("deploy_1"), 4)

        print("Deploy contract group 2")
        yield load(path("deploy_2"), 6)

        for tx in load(path("add_liquidity"), 4):
            print("Add liquidity in step")
            yield [tx]
        
        print("Distribute toke A")
        yield load(path("distribute_token_a"), self.accounts_n)
        print("Distribute native")
        yield load(path("distribute_native"), self.accounts_n)
        print("Approval")
        yield load(path("approval"), self.accounts_n * 2)[::2]

    def bench_transaction(self):
        path = lambda x: os.path.join(TRANSACTION_PATH, f"uniswap/{x}")
        return load(path(f"swap_eth_{self.accounts_n}"), self.tx_n)
        

def get_loader(options):
    if options.bench_token == "erc20":
        is_erc20 = True
    elif options.bench_token == "native":
        is_erc20 = False
    else:
        raise Exception("Unrecognized bench token")


    if options.bench_mode == "normal":
        return Erc20(options) if is_erc20 else Native(options)
    elif options.bench_mode == "less-sender":
        return Erc20LessSender(options) if is_erc20 else NativeLessSender(options)
    elif options.bench_mode == "uniswap":
        return Uniswap(options) if is_erc20 else UniswapETH(options)
    else:
        raise Exception("Unrecognized bench mode")
