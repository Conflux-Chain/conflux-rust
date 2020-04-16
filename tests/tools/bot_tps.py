#!/usr/bin/env python3

import os
import toml
import threading
import time
import random
import eth_utils
import sys
from jsonrpcclient.exceptions import ReceivedErrorResponseError

sys.path.append("..")
from test_framework.authproxy import JSONRPCException
from conflux.rpc import RpcClient
from conflux.utils import priv_to_addr
from test_framework.util import assert_equal, get_simple_rpc_proxy

DRIPS_PER_CFX = 10**18
INFLIGHT_NONCES = 1500


class Sender:

    def __init__(self, client: RpcClient, addr: str, priv_key_hex: str, balance: int, nonce: int):
        self.client = client
        self.addr = addr
        self.priv_key = eth_utils.decode_hex(priv_key_hex)
        self.balance = balance
        self.nonce = nonce

    @staticmethod
    def new(rpc_url: str, addr: str, priv_key_hex: str):
        client = new_client(rpc_url)
        balance = client.get_balance(addr)
        nonce = client.get_nonce(addr)
        return Sender(client, addr, priv_key_hex, balance, nonce)

    def new_sender(self, amount: int, rpc_url: str=None):
        (addr, priv_key) = self.client.rand_account()
        epoch_height = self.best_epoch_height()
        tx = self.client.new_tx(sender=self.addr, receiver=addr,
                                nonce=self.nonce, value=amount,
                                priv_key=self.priv_key, epoch_height=epoch_height)
        assert_equal(self.client.send_tx(tx), tx.hash_hex())

        self.balance -= self.client.DEFAULT_TX_FEE + amount
        self.nonce += 1

        client = self.client if rpc_url is None else new_client(rpc_url)
        sender = Sender(client, addr, priv_key, amount, 0)

        return sender

    def wait_for_balance(self, interval=1, retry=30):
        while retry >= 0:
            balance = self.client.get_balance(self.addr)
            if balance > 0:
                assert_equal(balance, self.balance)
                return
            else:
                time.sleep(interval)
            retry -= 1
        raise Exception("Wait for balance timeout after retrying")

    def account_nonce(self):
        return self.client.get_nonce(self.addr)

    def best_epoch_height(self):
        return self.client.epoch_number()

    def send(self, to: str, amount: int, epoch_height: int, retry_interval=5):
        tx = self.client.new_tx(sender=self.addr, receiver=to,
                                nonce=self.nonce, value=amount, priv_key=self.priv_key, epoch_height=epoch_height)
        while True:
            try:
                received_hash = self.client.send_tx(tx)
                print(f"sender={self.addr} nonce={self.nonce} hash={tx.hash_hex()} received_hash={received_hash}")
                assert_equal(tx.hash_hex(), received_hash)
                break
            except ReceivedErrorResponseError as e:
                if "tx already exist" in e.response.data or "stale" in e.response.data:
                    print(f"skip err={e.response} sender={self.addr} nonce={self.nonce}")
                    break
                else:
                    print("unexpected ReceivedErrorResponseError: ", e)
                    time.sleep(retry_interval)
            except Exception as e:
                print(f"failed to send tx: tx = {tx.as_dict()} err={e}")
                time.sleep(retry_interval)
        self.balance -= self.client.DEFAULT_TX_FEE + amount
        self.nonce += 1



class TpsWorker(threading.Thread):
    def __init__(self, sender: Sender, num_receivers: int):
        threading.Thread.__init__(self, daemon=False)
        self.sender = sender
        self.receivers = [sender.client.rand_addr()
                          for _ in range(num_receivers)]

    def run(self):
        try:
            while self.sender.balance > 30000:
                account_nonce = self.sender.account_nonce()
                epoch_height = self.sender.best_epoch_height()
                assert self.sender.nonce >= account_nonce
                print(f"get nonce for {self.sender.addr} {self.sender.client.node.url}: nonce={account_nonce}")
                if self.sender.nonce - account_nonce > INFLIGHT_NONCES:
                    time.sleep(3)
                    continue

                while self.sender.nonce - account_nonce <= INFLIGHT_NONCES:
                    to = self.receivers[random.randint(0, len(self.receivers) - 1)]
                    self.sender.send(to, 9000, epoch_height)
        except Exception as e:
            print(f"Exception during running: f{e}")


def load_boot_nodes():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_file_path = os.path.abspath(os.path.join(
        current_dir, "..", "..", "run", "default.toml"))
    if not os.path.exists(config_file_path):
        print("file not found:", config_file_path)
        sys.exit(1)

    nodes = []
    with open(config_file_path) as config_file:
        bootnodes = toml.loads(config_file.read())["bootnodes"]
        for node in bootnodes.split(","):
            ip = node.split("@")[1].split(":")[0]
            nodes.append("http://{0}:12537/".format(ip))

    return nodes


def new_client(rpc_url):
    return RpcClient(node=get_simple_rpc_proxy(rpc_url, timeout=10))


def work(faucet_addr, faucet_priv_key_hex, rpc_urls: list, num_threads: int, num_receivers: int):
    # init faucet
    print("Initialize faucet ...")
    faucet = Sender.new(rpc_urls[0], faucet_addr, faucet_priv_key_hex)
    print("Faucet: balance = {}, nonce = {}".format(
        faucet.balance, faucet.nonce))

    # init global sender for all nodes, so that only 1 tx required from faucet
    # account.
    print("Initialize global sender ...")
    global_sender = faucet.new_sender(
        (len(rpc_urls) * num_threads + 1) * DRIPS_PER_CFX)
    global_sender.wait_for_balance()
    print("Global sender: balance = {}, nonce = {}".format(
        global_sender.balance, global_sender.nonce))

    # init senders for all threads
    print("Initialize node/thread senders ...")
    all_senders = []
    for url in rpc_urls:
        for _ in range(num_threads):
            sender = global_sender.new_sender(DRIPS_PER_CFX, url)
            all_senders.append(sender)
    senders = []
    for sender in all_senders:
        while True:
            try:
                print("Check {} with addr {}".format(sender.client.node.url, sender.addr))
                sender.wait_for_balance()
                senders.append(sender)
                break
            except Exception as e:
                print(sender.client.node.url, "is not available for Exception", e)
                time.sleep(1)
                continue

    # start threads to send txs to different nodes
    print("begin to send txs ...")
    workers = []
    for s in senders:
        t = TpsWorker(s, num_receivers)
        workers.append(t)
        t.start()
    for w in workers:
        w.join()

# main
if len(sys.argv) == 1:
    print("faucet private key not specified.")
    sys.exit(1)

faucet_priv_key = sys.argv[1]
faucet_addr = eth_utils.encode_hex(priv_to_addr(faucet_priv_key))
bootnodes = load_boot_nodes()
num_threads = 1 if len(sys.argv) < 3 else int(sys.argv[2])
num_receivers = 20 if len(sys.argv) < 4 else int(sys.argv[3])
work(faucet_addr, faucet_priv_key, bootnodes, num_threads, num_receivers)
