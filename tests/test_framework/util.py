#!/usr/bin/env python3
from base64 import b64encode
from binascii import hexlify, unhexlify
from decimal import Decimal, ROUND_DOWN
import hashlib
import inspect
import json
import logging
import os
import random
import re
from subprocess import CalledProcessError
import time
import socket
import threading

import jsonrpcclient.exceptions

from test_framework.simple_rpc_proxy import SimpleRpcProxy
from . import coverage
from .authproxy import AuthServiceProxy, JSONRPCException

CONFLUX_RPC_WAIT_TIMEOUT = 60

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


def initialize_datadir(dirname, n, conf_parameters):
    datadir = get_datadir_path(dirname, n)
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    with open(
            os.path.join(datadir, "conflux.conf"), 'w', encoding='utf8') as f:
        local_conf = {"port": str(p2p_port(n)),
                        "jsonrpc_local_http_port": str(rpc_port(n)),
                        "jsonrpc_http_port": str(remote_rpc_port(n)),
                        "log_file": "\'{}\'".format(os.path.join(datadir, "conflux.log")),
                        "mode": "\'test\'",
                        "log_level": "\"trace\"",
                        "storage_delta_mpts_cache_size": "200000",
                        "storage_delta_mpts_cache_start_size": "200000",
                        "storage_delta_mpts_node_map_vec_size": "200000",
                        "start_mining":"false",
                        "subnet_quota": "0",
                        "session_ip_limits": "\"0,0,0,0\"",
                        "enable_discovery": "false",
                        "metrics_output_file": "\'{}\'".format(os.path.join(datadir, "metrics.log")),
                        "metrics_enabled": "true",
                        # "block_db_type": "\'sqlite\'"
                      }
        for k in conf_parameters:
            local_conf[k] = conf_parameters[k]
        for k in local_conf:
            f.write("{}={}\n".format(k, local_conf[k]))
        os.makedirs(os.path.join(datadir, 'stderr'), exist_ok=True)
        os.makedirs(os.path.join(datadir, 'stdout'), exist_ok=True)
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
        if peer["nodeid"] == target_node_id and len(peer['caps']) > 0:
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


def get_simple_rpc_proxy(url, node_number, timeout=CONFLUX_RPC_WAIT_TIMEOUT):
    return SimpleRpcProxy(url, timeout)


def p2p_port(n):
    assert (n <= MAX_NODES)
    return PORT_MIN + n + (MAX_NODES * PortSeed.n) % (
        PORT_RANGE - 1 - MAX_NODES)


def rpc_port(n):
    return PORT_MIN + PORT_RANGE + n*2 + (MAX_NODES * PortSeed.n) % (
        PORT_RANGE - 1 - MAX_NODES)

def remote_rpc_port(n):
    return rpc_port(n) + 1


def rpc_url(i, rpchost=None, rpcport=None):
    if rpchost is None:
        # Do not use localhost because our test environment doesn't support
        # IPv6 however the python http library assumes that.
        rpchost = "127.0.0.1"
    if rpcport is None:
        rpcport = rpc_port(i)
    return "http://%s:%d" % (rpchost, int(rpcport))


def get_ip_address():
    return [int(i) for i in socket.gethostbyname(socket.gethostname()).split('.')]


def checktx(node, tx_hash):
    return node.gettransactionreceipt(tx_hash) is not None


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
