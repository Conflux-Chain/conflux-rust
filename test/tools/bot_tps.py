import os
import toml
import threading
import time
import random
import eth_utils

import sys
sys.path.append("..")

from conflux.rpc import RpcClient
from test_framework.util import get_rpc_proxy, assert_equal

DRIPS_PER_CFX = 10**18

class Sender:
    def __init__(self, client:RpcClient, addr:str, priv_key_hex:str, balance:int, nonce:int):
        self.client = client
        self.addr = addr
        self.priv_key = eth_utils.decode_hex(priv_key_hex)
        self.balance = balance
        self.nonce = nonce

    @staticmethod
    def new(rpc_url:str, addr:str, priv_key_hex:str):
        client = new_client(rpc_url)
        balance = client.get_balance(addr)
        nonce = client.get_nonce(addr)
        return Sender(client, addr, priv_key_hex, balance, nonce)

    def new_sender(self, amount:int, rpc_url:str=None):
        (addr, priv_key) = self.client.rand_account()
        tx = self.client.new_tx(sender=self.addr, receiver=addr, nonce=self.nonce, value=amount, priv_key=self.priv_key)
        assert_equal(self.client.send_tx(tx), tx.hash_hex())

        self.balance -= 21000 + amount
        self.nonce += 1

        client = self.client if rpc_url is None else new_client(rpc_url)
        sender = Sender(client, addr, priv_key, amount, 0)

        return sender

    def wait_for_balance(self):
        while True:
            balance = self.client.get_balance(self.addr)
            if balance > 0:
                assert_equal(balance, self.balance)
                break
            else:
                time.sleep(1)

    def account_nonce(self):
        return self.client.get_nonce(self.addr)

    def send(self, to:str, amount:int):
        tx = self.client.new_tx(sender=self.addr, receiver=to, nonce=self.nonce, value=amount, priv_key=self.priv_key)

        while True:
            try:
                self.client.send_tx(tx)
                break
            except Exception as e:
                print("failed to send tx:", e)
                time.sleep(5)

        self.balance -= 30000
        self.nonce += 1

class TpsWorker(threading.Thread):
    def __init__(self, sender:Sender, num_receivers:int):
        threading.Thread.__init__(self, daemon=False)
        self.sender = sender
        self.receivers = [sender.client.rand_addr() for _ in range(num_receivers)]

    def run(self):
        while self.sender.balance > 30000:
            account_nonce = self.sender.account_nonce()
            assert self.sender.nonce >= account_nonce
            if self.sender.nonce - account_nonce > 2000:
                time.sleep(3)
                continue

            while self.sender.nonce - account_nonce <= 2000:
                to = self.receivers[random.randint(0, len(self.receivers) - 1)]
                self.sender.send(to, 9000)

def load_boot_nodes():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_file_path = os.path.abspath(os.path.join(current_dir, "..", "..", "run", "default.toml"))
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
    return RpcClient(node=get_rpc_proxy(rpc_url, 3))

def work(faucet_addr, faucet_priv_key_hex, rpc_urls:list, num_threads:int, num_receivers:int):
    # init faucet
    print("Initialize faucet ...")
    faucet = Sender.new(rpc_urls[0], faucet_addr, faucet_priv_key_hex)
    print("Faucet: balance = {}, nonce = {}".format(faucet.balance, faucet.nonce))

    # init global sender for all nodes, so that only 1 tx required from faucet account.
    print("Initialize global sender ...")
    global_sender = faucet.new_sender((len(rpc_urls) * num_threads + 1) * DRIPS_PER_CFX)
    global_sender.wait_for_balance()
    print("Global sender: balance = {}, nonce = {}".format(global_sender.balance, global_sender.nonce))

    # init senders for all threads
    print("Initialize node/thread senders ...")
    senders = []
    for url in rpc_urls:
        for _ in range(num_threads):
            sender = global_sender.new_sender(DRIPS_PER_CFX, url)
            senders.append(sender)
    for s in senders:
        s.wait_for_balance()
        # print("\tnode sender: balance = {}, nonce = {}".format(s.balance, s.nonce))

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
faucet_addr = "0xa70ddf9b9750c575db453eea6a041f4c8536785a"
faucet_priv_key = "4bb79797807812587dd6e02b39fee03056c11eec5ec599609d9175a1275a9a10"
bootnodes = load_boot_nodes()
work(faucet_addr, faucet_priv_key, bootnodes, 1, 20)