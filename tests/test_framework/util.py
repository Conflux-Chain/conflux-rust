#!/usr/bin/env python3
from base64 import b64encode
from binascii import hexlify, unhexlify

import conflux.config
from decimal import Decimal, ROUND_DOWN
import hashlib
import inspect
import json
import logging
import os
import random
import re
from subprocess import CalledProcessError, check_call
import time
import socket
import threading
import jsonrpcclient.exceptions
import solcx
import web3

from test_framework.simple_rpc_proxy import SimpleRpcProxy
from . import coverage
from .authproxy import AuthServiceProxy, JSONRPCException

solcx.set_solc_version('v0.5.17')

CONFLUX_RPC_WAIT_TIMEOUT = 60
CONFLUX_GRACEFUL_SHUTDOWN_TIMEOUT = 1220

logger = logging.getLogger("TestFramework.utils")

# Assert functions
##################


def assert_fee_amount(fee, tx_size, fee_per_kB):
    """Assert the fee was in range"""
    target_fee = round(tx_size * fee_per_kB / 1000, 8)
    if fee < target_fee:
        raise AssertionError("Fee of %s BTC too low! (Should be %s BTC)" %
                             (str(fee), str(target_fee)))
    # allow the wallet's estimation to be at most 2 bytes off
    if fee > (tx_size + 2) * fee_per_kB / 1000:
        raise AssertionError("Fee of %s BTC too high! (Should be %s BTC)" %
                             (str(fee), str(target_fee)))


def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(
            str(arg) for arg in (thing1, thing2) + args))


def assert_greater_than(thing1, thing2):
    if thing1 <= thing2:
        raise AssertionError("%s <= %s" % (str(thing1), str(thing2)))


def assert_greater_than_or_equal(thing1, thing2):
    if thing1 < thing2:
        raise AssertionError("%s < %s" % (str(thing1), str(thing2)))


def assert_raises(exc, fun, *args, **kwds):
    assert_raises_message(exc, None, fun, *args, **kwds)


def assert_raises_message(exc, message, fun, *args, **kwds):
    try:
        fun(*args, **kwds)
    except JSONRPCException:
        raise AssertionError(
            "Use assert_raises_rpc_error() to test RPC failures")
    except exc as e:
        if message is not None and message not in e.error['message']:
            raise AssertionError("Expected substring not found:" +
                                 e.error['message'])
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " +
                             type(e).__name__)
    else:
        raise AssertionError("No exception raised")


def assert_raises_process_error(returncode, output, fun, *args, **kwds):
    """Execute a process and asserts the process return code and output.

    Calls function `fun` with arguments `args` and `kwds`. Catches a CalledProcessError
    and verifies that the return code and output are as expected. Throws AssertionError if
    no CalledProcessError was raised or if the return code and output are not as expected.

    Args:
        returncode (int): the process return code.
        output (string): [a substring of] the process output.
        fun (function): the function to call. This should execute a process.
        args*: positional arguments for the function.
        kwds**: named arguments for the function.
    """
    try:
        fun(*args, **kwds)
    except CalledProcessError as e:
        if returncode != e.returncode:
            raise AssertionError("Unexpected returncode %i" % e.returncode)
        if output not in e.output:
            raise AssertionError("Expected substring not found:" + e.output)
    else:
        raise AssertionError("No exception raised")


def assert_raises_rpc_error(code, message, fun, *args, **kwds):
    """Run an RPC and verify that a specific JSONRPC exception code and message is raised.

    Calls function `fun` with arguments `args` and `kwds`. Catches a JSONRPCException
    and verifies that the error code and message are as expected. Throws AssertionError if
    no JSONRPCException was raised or if the error code/message are not as expected.

    Args:
        code (int), optional: the error code returned by the RPC call (defined
            in src/rpc/protocol.h). Set to None if checking the error code is not required.
        message (string), optional: [a substring of] the error string returned by the
            RPC call. Set to None if checking the error string is not required.
        fun (function): the function to call. This should be the name of an RPC.
        args*: positional arguments for the function.
        kwds**: named arguments for the function.
    """
    assert try_rpc(code, message, fun, *args, **kwds), "No exception raised"


def try_rpc(code, message, fun, *args, **kwds):
    """Tries to run an rpc command.

    Test against error code and message if the rpc fails.
    Returns whether a JSONRPCException was raised."""
    try:
        fun(*args, **kwds)
    except jsonrpcclient.exceptions.ReceivedErrorResponseError as e:
        error = e.response
        # JSONRPCException was thrown as expected. Check the code and message values are correct.
        if (code is not None) and (code != error.code):
            raise AssertionError(
                "Unexpected JSONRPC error code %i" % error.code)
        if (message is not None) and (message not in error.message):
            raise AssertionError("Expected substring not found:" +
                                 error.message)
        return True
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " +
                             type(e).__name__)
    else:
        return False


def assert_is_hex_string(string):
    try:
        int(string, 16)
    except Exception as e:
        raise AssertionError(
            "Couldn't interpret %r as hexadecimal; raised: %s" % (string, e))

def assert_is_hash_string(string, length=64):
    if not isinstance(string, str):
        raise AssertionError("Expected a string, got type %r" % type(string))

    if string.startswith("0x"):
        string = string[2:]
   
    if length and len(string) != length:
        raise AssertionError(
            "String of length %d expected; got %d" % (length, len(string)))
    
    if not re.match('[abcdef0-9]+$', string):
        raise AssertionError(
            "String %r contains invalid characters for a hash." % string)


def assert_array_result(object_array,
                        to_match,
                        expected,
                        should_not_find=False):
    """
        Pass in array of JSON objects, a dictionary with key/value pairs
        to match against, and another dictionary with expected key/value
        pairs.
        If the should_not_find flag is true, to_match should not be found
        in object_array
        """
    if should_not_find:
        assert_equal(expected, {})
    num_matched = 0
    for item in object_array:
        all_match = True
        for key, value in to_match.items():
            if item[key] != value:
                all_match = False
        if not all_match:
            continue
        elif should_not_find:
            num_matched = num_matched + 1
        for key, value in expected.items():
            if item[key] != value:
                raise AssertionError(
                    "%s : expected %s=%s" % (str(item), str(key), str(value)))
            num_matched = num_matched + 1
    if num_matched == 0 and not should_not_find:
        raise AssertionError("No objects matched %s" % (str(to_match)))
    if num_matched > 0 and should_not_find:
        raise AssertionError("Objects were found %s" % (str(to_match)))


# Utility functions
###################


def check_json_precision():
    """Make sure json library being used does not lose precision converting BTC values"""
    n = Decimal("20000000.00000003")
    satoshis = int(json.loads(json.dumps(float(n))) * 1.0e8)
    if satoshis != 2000000000000003:
        raise RuntimeError("JSON encode/decode loses precision")

def satoshi_round(amount):
    return Decimal(amount).quantize(Decimal('0.00000001'), rounding=ROUND_DOWN)


def wait_until(predicate,
               *,
               attempts=float('inf'),
               timeout=float('inf'),
               lock=None):
    if attempts == float('inf') and timeout == float('inf'):
        timeout = 60
    attempt = 0
    time_end = time.time() + timeout

    while attempt < attempts and time.time() < time_end:
        if lock:
            with lock:
                if predicate():
                    return
        else:
            if predicate():
                return
        attempt += 1
        time.sleep(0.5)

    # Print the cause of the timeout
    predicate_source = inspect.getsourcelines(predicate)
    logger.error("wait_until() failed. Predicate: {}".format(predicate_source))
    if attempt >= attempts:
        raise AssertionError("Predicate {} not true after {} attempts".format(
            predicate_source, attempts))
    elif time.time() >= time_end:
        raise AssertionError("Predicate {} not true after {} seconds".format(
            predicate_source, timeout))
    raise RuntimeError('Unreachable')


# Node functions
################

def initialize_tg_config(dirname, nodes):
    tg_config_gen = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../target/release/tg_config_gen")
    check_call([tg_config_gen, "random", "--num-validator={}".format(nodes)], cwd=dirname)
    consensus_peers_config = open(os.path.join(dirname, "consensus_peers.config.toml")).readlines()
    private_keys = open(os.path.join(dirname, "private_key")).readlines()
    print('consensus_peers_config: {}'.format(consensus_peers_config))
    print('private_keys: {}'.format(private_keys))
    for n in range(nodes):
        datadir = get_datadir_path(dirname, n)
        if not os.path.isdir(datadir):
            os.makedirs(datadir)
        os.makedirs(os.path.join(datadir, 'net_config'))
        os.makedirs(os.path.join(datadir, 'tg_config'))
        with open(os.path.join(datadir, 'tg_config', 'tg_config.conf'), 'w') as f:
            base_local_conf = {
                "role": "\"validator\""
            }
            f.write("enable_state_expose=true\n")
            f.write("[base]\n")
            for k in base_local_conf:
                f.write("{}={}\n".format(k, base_local_conf[k]))
            consensus_local_conf = {
                "consensus_peers_file": "\"consensus_peers.config.toml\""
            }
            f.write("\n[consensus]\n")
            for k in consensus_local_conf:
                f.write("{}={}\n".format(k, consensus_local_conf[k]))
        with open(os.path.join(datadir, 'tg_config', 'consensus_peers.config.toml'), 'w') as f:
            for line in consensus_peers_config:
                f.write(line)
        with open(os.path.join(datadir, 'net_config', 'key'), 'w') as f:
            f.write(private_keys[n])

def initialize_datadir(dirname, n, conf_parameters, extra_files: dict = {}):
    datadir = get_datadir_path(dirname, n)
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    with open(
            os.path.join(datadir, "conflux.conf"), 'w', encoding='utf8') as f:
        local_conf = {
            "port": str(p2p_port(n)),
            "jsonrpc_local_http_port": str(rpc_port(n)),
            "jsonrpc_ws_port": str(pubsub_port(n)),
            "jsonrpc_http_port": str(remote_rpc_port(n)),
            "tg_config_path": "\'{}\'".format(os.path.join(datadir, "tg_config/tg_config.conf")),
        }
        local_conf.update(conflux.config.small_local_test_conf)
        local_conf.update(conf_parameters)
        for k in local_conf:
            f.write("{}={}\n".format(k, local_conf[k]))
        os.makedirs(os.path.join(datadir, 'stderr'), exist_ok=True)
        os.makedirs(os.path.join(datadir, 'stdout'), exist_ok=True)
    for file_name, content in extra_files.items():
        with open(os.path.join(datadir, file_name), 'w', encoding='utf8') as f:
            f.write(content)
    return datadir


def get_datadir_path(dirname, n):
    return os.path.join(dirname, "node" + str(n))


def append_config(datadir, options):
    with open(
            os.path.join(datadir, "bitcoin.conf"), 'a', encoding='utf8') as f:
        for option in options:
            f.write(option + "\n")


def get_auth_cookie(datadir):
    user = None
    password = None
    if os.path.isfile(os.path.join(datadir, "bitcoin.conf")):
        with open(
                os.path.join(datadir, "bitcoin.conf"), 'r',
                encoding='utf8') as f:
            for line in f:
                if line.startswith("rpcuser="):
                    assert user is None  # Ensure that there is only one rpcuser line
                    user = line.split("=")[1].strip("\n")
                if line.startswith("rpcpassword="):
                    assert password is None  # Ensure that there is only one rpcpassword line
                    password = line.split("=")[1].strip("\n")
    if os.path.isfile(os.path.join(datadir, "regtest", ".cookie")):
        with open(
                os.path.join(datadir, "regtest", ".cookie"), 'r',
                encoding="ascii") as f:
            userpass = f.read()
            split_userpass = userpass.split(':')
            user = split_userpass[0]
            password = split_userpass[1]
    if user is None or password is None:
        raise ValueError("No RPC credentials")
    return user, password


# If a cookie file exists in the given datadir, delete it.
def delete_cookie_file(datadir):
    if os.path.isfile(os.path.join(datadir, "regtest", ".cookie")):
        logger.debug("Deleting leftover cookie file")
        os.remove(os.path.join(datadir, "regtest", ".cookie"))


def get_bip9_status(node, key):
    info = node.getblockchaininfo()
    return info['bip9_softforks'][key]


def set_node_times(nodes, t):
    for node in nodes:
        node.setmocktime(t)


def disconnect_nodes(nodes, from_connection, node_num):
    try:
        nodes[from_connection].removenode(nodes[node_num].key, get_peer_addr(nodes[node_num]))
        nodes[node_num].removenode(nodes[from_connection].key, get_peer_addr(nodes[from_connection]))
    except JSONRPCException as e:
        # If this node is disconnected between calculating the peer id
        # and issuing the disconnect, don't worry about it.
        # This avoids a race condition if we're mass-disconnecting peers.
        if e.error['code'] != -29:  # RPC_CLIENT_NODE_NOT_CONNECTED
            raise

    # wait to disconnect
    wait_until(lambda: [peer for peer in nodes[from_connection].getpeerinfo() if peer["nodeid"] == nodes[node_num].key] == [], timeout=5)
    wait_until(lambda: [peer for peer in nodes[node_num].getpeerinfo() if peer["nodeid"] == nodes[from_connection].key] == [], timeout=5)


def check_handshake(from_connection, target_node_id):
    """
    Check whether node 'from_connection' has already
    added node 'target_node_id' into its peer set.
    """
    peers = from_connection.getpeerinfo()
    for peer in peers:
        if peer["nodeid"] == target_node_id and len(peer['protocols']) > 0:
            return True
    return False


def get_peer_addr(connection):
    return "{}:{}".format(connection.ip, connection.port)


def connect_nodes(nodes, a, node_num, timeout=60):
    """
    Let node[a] connect to node[node_num]
    """
    from_connection = nodes[a]
    to_connection = nodes[node_num]
    key = nodes[node_num].key
    peer_addr = get_peer_addr(to_connection)
    from_connection.addnode(key, peer_addr)
    # poll until hello handshake complete to avoid race conditions
    # with transaction relaying
    wait_until(lambda: check_handshake(from_connection, to_connection.key), timeout=timeout)


def sync_blocks(rpc_connections, *, sync_count=True, wait=1, timeout=60):
    """
    Wait until everybody has the same tip.

    sync_blocks needs to be called with an rpc_connections set that has least
    one node already synced to the latest, stable tip, otherwise there's a
    chance it might return before all nodes are stably synced.
    """
    stop_time = time.time() + timeout
    while time.time() <= stop_time:
        best_hash = [x.best_block_hash() for x in rpc_connections]
        block_count = [x.getblockcount() for x in rpc_connections]
        if best_hash.count(best_hash[0]) == len(rpc_connections) and (not sync_count or block_count.count(block_count[0]) == len(rpc_connections)):
            return
        time.sleep(wait)
    raise AssertionError("Block sync timed out:{}".format("".join(
        "\n  {!r}".format(b) for b in best_hash + block_count)))


def sync_mempools(rpc_connections, *, wait=1, timeout=60,
                  flush_scheduler=True):
    """
    Wait until everybody has the same transactions in their memory
    pools
    """
    stop_time = time.time() + timeout
    while time.time() <= stop_time:
        pool = [set(r.getrawmempool()) for r in rpc_connections]
        if pool.count(pool[0]) == len(rpc_connections):
            if flush_scheduler:
                for r in rpc_connections:
                    r.syncwithvalidationinterfacequeue()
            return
        time.sleep(wait)
    raise AssertionError("Mempool sync timed out:{}".format("".join(
        "\n  {!r}".format(m) for m in pool)))


def wait_for_block_count(node, count, timeout=10):
    wait_until(lambda: node.getblockcount() >= count, timeout=timeout)


class WaitHandler:
    def __init__(self, node, msgid, func=None):
        self.keep_wait = True
        self.node = node
        self.msgid = msgid

        def on_message(obj, msg):
            if func is not None:
                func(obj, msg)
            self.keep_wait = False
        node.set_callback(msgid, on_message)

    def wait(self, timeout=10):
        wait_until(lambda: not self.keep_wait, timeout=timeout)
        self.node.reset_callback(self.msgid)


# RPC/P2P connection constants and functions
############################################

# The maximum number of nodes a single test can spawn
MAX_NODES = 100
# Don't assign rpc or p2p ports lower than this
PORT_MIN = 11000
# The number of ports to "reserve" for p2p and rpc, each
PORT_RANGE = 5000


class PortSeed:
    # Must be initialized with a unique integer for each process
    n = None


def get_rpc_proxy(url, node_number, timeout=CONFLUX_RPC_WAIT_TIMEOUT, coveragedir=None):
    """
    Args:
        url (str): URL of the RPC server to call
        node_number (int): the node number (or id) that this calls to

    Kwargs:
        timeout (int): HTTP timeout in seconds

    Returns:
        AuthServiceProxy. convenience object for making RPC calls.

    """
    proxy_kwargs = {}
    if timeout is not None:
        proxy_kwargs['timeout'] = timeout

    proxy = AuthServiceProxy(url, **proxy_kwargs)
    proxy.url = url  # store URL on proxy for info

    coverage_logfile = coverage.get_filename(
        coveragedir, node_number) if coveragedir else None

    return coverage.AuthServiceProxyWrapper(proxy, coverage_logfile)


def get_simple_rpc_proxy(url, node=None, timeout=CONFLUX_RPC_WAIT_TIMEOUT):
    return SimpleRpcProxy(url, timeout, node)


def p2p_port(n):
    assert (n <= MAX_NODES)
    return PORT_MIN + n + (MAX_NODES * PortSeed.n) % (
        PORT_RANGE - 1 - MAX_NODES)


def rpc_port(n):
    return PORT_MIN + PORT_RANGE + n*3 + (MAX_NODES * PortSeed.n) % (
        PORT_RANGE - 1 - MAX_NODES)

def remote_rpc_port(n):
    return rpc_port(n) + 1

def pubsub_port(n):
    return rpc_port(n) + 2


def rpc_url(i, rpchost=None, rpcport=None):
    if rpchost is None:
        # Do not use localhost because our test environment doesn't support
        # IPv6 however the python http library assumes that.
        rpchost = "127.0.0.1"
    if rpcport is None:
        rpcport = rpc_port(i)
    return "http://%s:%d" % (rpchost, int(rpcport))


def pubsub_url(i, pubsubhost=None, pubsubport=None):
    if pubsubhost is None:
        # Do not use localhost because our test environment doesn't support
        # IPv6 however the python http library assumes that.
        pubsubhost = "127.0.0.1"
    if pubsubport is None:
        pubsubport = pubsub_port(i)
    return "ws://%s:%d" % (pubsubhost, int(pubsubport))


def get_ip_address():
    return [int(i) for i in socket.gethostbyname(socket.gethostname()).split('.')]


def checktx(node, tx_hash):
    return node.cfx_getTransactionReceipt(tx_hash) is not None


def connect_sample_nodes(nodes, log, sample=3, latency_min=0, latency_max=300, timeout=30):
    """
    Establish connections among nodes with each node having 'sample' outgoing peers.
    It first lets all the nodes link as a loop, then randomly pick 'sample-1'
    outgoing peers for each node.    
    """
    peer = [[] for _ in nodes]
    latencies = [{} for _ in nodes]
    threads = []
    num_nodes = len(nodes)
    sample = min(num_nodes - 1, sample)

    for i in range(num_nodes):
        # make sure all nodes are reachable
        next = (i + 1) % num_nodes
        peer[i].append(next)
        lat = random.randint(latency_min, latency_max)
        latencies[i][next] = lat
        latencies[next][i] = lat

        for _ in range(sample - 1):
            while True:
                p = random.randint(0, num_nodes - 1)
                if p not in peer[i] and not p == i:
                    peer[i].append(p)
                    lat = random.randint(latency_min, latency_max)
                    latencies[i][p] = lat
                    latencies[p][i] = lat
                    break

    for i in range(num_nodes):
        t = ConnectThread(nodes, i, peer[i], latencies, log, min_peers=sample)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout)
        assert not t.is_alive(), "Node[{}] connect to other nodes timeout in {} seconds".format(t.a, timeout)
        assert not t.failed, "connect_sample_nodes failed."


def assert_blocks_valid(nodes, blocks):
    for node in nodes:
        for block in blocks:
            r = node.get_block_status(block)
            assert_equal(r[0], 0)  # block status is valid
            assert_equal(r[1], True)  # state_valid is True


class ConnectThread(threading.Thread):
    def __init__(self, nodes, a, peers, latencies, log, min_peers=3, daemon=True):
        threading.Thread.__init__(self, daemon=daemon)
        self.nodes = nodes
        self.a = a
        self.peers = peers
        self.latencies = latencies
        self.log = log
        self.min_peers = min_peers
        self.failed = False

    def run(self):
        try:
            while True:
                for i in range(len(self.peers)):
                    p = self.peers[i]
                    connect_nodes(self.nodes, self.a, p)
                for p in self.latencies[self.a]:
                    self.nodes[self.a].addlatency(self.nodes[p].key, self.latencies[self.a][p])
                if len(self.nodes[self.a].getpeerinfo()) >= self.min_peers:
                    break
                else:
                    time.sleep(1)
        except Exception as e:
            node = self.nodes[self.a]
            self.log.error("Node " + str(self.a) + " fails to be connected to " + str(self.peers) + ", ip={}, index={}".format(node.ip, node.index))
            self.log.error(e)
            self.failed = True


def get_contract_instance(contract_dict=None,
                          source=None,
                          contract_name=None,
                          address=None,
                          abi_file=None,
                          bytecode_file=None):
    w3 = web3.Web3()
    contract = None
    if source and contract_name:
        output = solcx.compile_files([source])
        contract_dict = output[f"{source}:{contract_name}"]
        if "bin" in contract_dict:
            contract_dict["bytecode"] = contract_dict.pop("bin")
        elif "code" in contract_dict:
            contract_dict["bytecode"] = contract_dict.pop("code")
    if contract_dict:
        contract = w3.eth.contract(
            abi=contract_dict['abi'], bytecode=contract_dict['bytecode'], address=address)
    elif abi_file:
        with open(abi_file, 'r') as abi_file:
            abi = json.loads(abi_file.read())
        if address:
            contract = w3.eth.contract(abi=abi, address=address)
        elif bytecode_file:
            bytecode = None
            if bytecode_file:
                with open(bytecode_file, 'r') as bytecode_file:
                    bytecode = bytecode_file.read()
                contract = w3.eth.contract(abi=abi, bytecode=bytecode)
            else:
                raise ValueError("The bytecode or the address must be provided")
    return contract


class PoWGenerateThread(threading.Thread):
    def __init__(self, name, node, generation_period_ms, log, report_progress_blocks=None, fixed_period=False):
        threading.Thread.__init__(self, daemon=True)
        self.name = name
        self.node = node
        self.generation_period_ms = generation_period_ms
        self.log = log
        self.report_progress_blocks = report_progress_blocks
        self.fixed_period = fixed_period

    def generate_block(self):
        pass

    def run(self):
        # generate blocks
        i = 0
        period_start_time = time.time()
        while True:
            i += 1
            if self.report_progress_blocks is not None:
                if i % self.report_progress_blocks == 0:
                    period_elapsed = time.time() - period_start_time
                    self.log.info("[%s]: %d blocks generated in %f seconds", self.name, self.report_progress_blocks, period_elapsed)
                    period_start_time = time.time()

            if self.fixed_period:
                wait_sec = self.generation_period_ms / 1000
            else:
                wait_sec = random.expovariate(1000 / self.generation_period_ms)
            start = time.time()
            self.generate_block()
            elapsed = time.time() - start
            if elapsed < wait_sec:
                time.sleep(wait_sec - elapsed)
