#!/usr/bin/env python3

import integration_tests.conflux.config
from decimal import Decimal, ROUND_DOWN
import inspect
import json
import logging
import os
import random
import re
from subprocess import CalledProcessError, check_output
import time
from typing import Optional, Callable, List, TYPE_CHECKING, cast, Tuple, Union, Literal
import socket
import threading
import conflux_web3 # should be imported before web3
import web3
from cfx_account import Account as CfxAccount
from cfx_account.signers.local import LocalAccount  as CfxLocalAccount
from sys import platform
import yaml
import shutil
import math
from os.path import dirname, join
from pathlib import Path
from web3.exceptions import Web3RPCError, ContractLogicError

from integration_tests.test_framework.simple_rpc_proxy import SimpleRpcProxy, ReceivedErrorResponseError
from .. import coverage
from ..authproxy import AuthServiceProxy, JSONRPCException
if TYPE_CHECKING:
    from conflux.rpc import RpcClient

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
    
    
def assert_storage_occupied(receipt, addr, expected):
    if receipt["storageCoveredBySponsor"]:
        assert_equal(receipt["to"], addr.lower())
    else:
        assert_equal(receipt["from"], addr.lower())
    assert_equal(receipt["storageCollateralized"], expected)


def assert_storage_released(receipt, addr, expected):
    assert_equal(receipt["storageReleased"].get(addr.lower(), 0), expected)


def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(
            str(arg) for arg in (thing1, thing2) + args))


def assert_ne(thing1, thing2):
    if thing1 == thing2:
        raise AssertionError("not(%s)" % " != ".join([thing1, thing2]))


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


def assert_raises_rpc_error(code: Optional[int], message: Optional[str], fun: Callable, *args, err_data_: Optional[str]=None, **kwds):
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
    assert try_rpc(code, message, fun, err_data_, *args, **kwds), "No exception raised"


def try_rpc(code: Optional[int], message: Optional[str], fun: Callable, err_data_: Optional[str]=None, *args, **kwds):
    """Tries to run an rpc command.

    Test against error code and message if the rpc fails.
    Returns whether a JSONRPCException was raised."""
    try:
        fun(*args, **kwds)
    except ReceivedErrorResponseError as e:
        error = e.response
        # JSONRPCException was thrown as expected. Check the code and message values are correct.
        if (code is not None) and (code != error.code):
            raise AssertionError(
                "Unexpected JSONRPC error code %i" % error.code)
        if (message is not None) and (message not in cast(str, error.message)):
            raise AssertionError(f"Expected substring not found: {error.message}")
        if (err_data_ is not None):
            if not getattr(error, "data", None) or (err_data_ not in cast(str, error.data)):
                raise AssertionError(f"Expected substring not found: {error.data}")
        return True
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " +
                             type(e).__name__)
    else:
        return False
    
def assert_raises_web3_rpc_error(code: Optional[int], message: Optional[str], fun: Callable, *args, err_data_: Optional[str]=None, **kwds):
    try:
        fun(*args, **kwds)
    except Web3RPCError as e:
        error = e.rpc_response['error']
        # JSONRPCException was thrown as expected. Check the code and message values are correct.
        if (code is not None) and (code != error["code"]):
            raise AssertionError(
                "Unexpected JSONRPC error code %i" % error["code"])
        if (message is not None) and (message not in cast(str, error['message'])):
            raise AssertionError(f"Expected substring not found: {error['message']}")
        if (err_data_ is not None):
            if not getattr(error, "data", None) or (err_data_ not in cast(str, error['data'])):
                raise AssertionError(f"Expected substring not found: {error['data']}")
        return True
    except ContractLogicError as e:
        if (message is not None) and (message not in e.message):
            raise AssertionError(f"Expected substring not found: {e.message}")
        if (err_data_ is not None):
            if not getattr(e, "data", None) or (err_data_ not in cast(str, e.data)):
                raise AssertionError(f"Expected substring not found: {e.data}")
    except Exception as e:
        raise AssertionError("Unexpected exception raised: " + type(e).__name__)
    else:
        return False


def assert_is_hex_string(string):
    try:
        if string != "0x":
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

def initialize_tg_config(dirname, nodes, genesis_nodes, chain_id, initial_seed="0"*64, start_index=None, pkfile=None, pos_round_time_ms=1000, conflux_binary_path=None):
    if conflux_binary_path is None:
        tg_config_gen = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../target/release/pos-genesis-tool")
    else:
        tg_config_gen = os.path.join(os.path.dirname(conflux_binary_path), "pos-genesis-tool")
    try:
        if pkfile is None:
            check_output([tg_config_gen, "random", "--num-validator={}".format(nodes),
                    "--num-genesis-validator={}".format(genesis_nodes), "--chain-id={}".format(chain_id),
                          "--initial-seed={}".format(initial_seed)], cwd=dirname)
        else:
            print([tg_config_gen, "frompub", pkfile], dirname)
            check_output([tg_config_gen, "frompub", "--initial-seed={}".format(initial_seed), pkfile], cwd=dirname)
    except CalledProcessError as e:
        print(e.output)
    if start_index is None:
        start_index = 0
    for n in range(start_index, start_index + nodes):
        set_node_pos_config(dirname, n, pos_round_time_ms=pos_round_time_ms)


def set_node_pos_config(dirname, n, setup_keys=True, pos_round_time_ms=1000, hardcoded_epoch_committee=None):
    waypoint_path = os.path.join(dirname, 'waypoint_config')
    genesis_path = os.path.join(dirname, 'genesis_file')
    waypoint = open(waypoint_path, 'r').readlines()[0].strip()
    private_keys_dir = os.path.join(dirname, "private_keys")
    datadir = get_datadir_path(dirname, n)
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    net_config_dir = os.path.join(datadir, 'blockchain_data', 'net_config')
    os.makedirs(net_config_dir, exist_ok = True)
    os.makedirs(os.path.join(datadir, 'pos_db'), exist_ok = True)
    validator_config = {}
    validator_config['base'] = {
        'data_dir': os.path.join(datadir, 'pos_db'),
        'role': 'validator',
        'waypoint': {
            'from_config': waypoint,
        }
    }
    validator_config['execution'] = {
        'genesis_file_location': genesis_path,
    }
    validator_config['storage'] = {
        'dir': os.path.join(datadir, 'pos_db', 'db'),
    }
    validator_config['consensus'] = {
        'safety_rules': {
            'service': {
                'type': "local",
            }
        },
        'round_initial_timeout_ms': pos_round_time_ms,
    }
    if hardcoded_epoch_committee is not None:
        validator_config['consensus']['hardcoded_epoch_committee'] = hardcoded_epoch_committee
    validator_config['logger'] = {
        'level': "TRACE",
        'file': os.path.join(datadir, "pos.log")
    }
    validator_config['mempool'] = {
        "shared_mempool_tick_interval_ms": 200,
    }
    with open(os.path.join(datadir, 'validator_full_node.yaml'), 'w') as f:
        f.write(yaml.dump(validator_config, default_flow_style=False))
    if setup_keys:
        shutil.copyfile(os.path.join(private_keys_dir, str(n)), os.path.join(net_config_dir, 'pos_key'))
        shutil.copyfile(os.path.join(private_keys_dir, "pow_sk"+str(n)), os.path.join(datadir, 'pow_sk'))


def _will_create_genesis_secret_file(conf_parameters, core_secrets: list[str], evm_secrets: list[str]):
    if conf_parameters.get("genesis_secrets") == None:
        return len(core_secrets) > 1 or len(evm_secrets) > 1  # initial genesis secrets are already set
    if conf_parameters.get("genesis_secrets") and (len(core_secrets) > 0 or len(evm_secrets) > 0):
        warnings.warn("genesis_secrets is set and extra secrets are provided. extra secrets will be ignored.")
    return False

def initialize_datadir(dirname, n, port_min, conf_parameters, extra_files: dict = {}, core_secrets: list[str] = [], evm_secrets: list[str] = []):
    datadir = get_datadir_path(dirname, n)
    if not os.path.isdir(datadir):
        os.makedirs(datadir)

    if _will_create_genesis_secret_file(conf_parameters, core_secrets, evm_secrets):
        genesis_file_path = os.path.join(datadir, "genesis_secrets.txt")
        with open(genesis_file_path, 'w') as f:
            for secret in core_secrets:
                f.write(secret + "\n")
            conf_parameters.update({"genesis_secrets": f"\"{genesis_file_path}\""})
        genesis_evm_file_path = os.path.join(datadir, "genesis_evm_secrets.txt")
        with open(genesis_evm_file_path, 'w') as f:
            for secret in evm_secrets:
                f.write(secret + "\n")
            conf_parameters.update({"genesis_evm_secrets": f"\"{genesis_evm_file_path}\""})

    with open(
            os.path.join(datadir, "conflux.conf"), 'w', encoding='utf8') as f:
        local_conf = {
            "tcp_port": str(p2p_port(n)),
            "jsonrpc_local_http_port": str(rpc_port(n)),
            "jsonrpc_ws_port": str(pubsub_port(n)),
            "jsonrpc_http_port": str(remote_rpc_port(n)),
            "jsonrpc_http_eth_port": str(evm_rpc_port(n)),
            "jsonrpc_ws_eth_port": str(evm_rpc_ws_port(n)),
            "jsonrpc_http_eth_port_v2": str(evm_rpc_port_v2(n)), # the async espace rpc port
            "pos_config_path": "\'{}\'".format(os.path.join(datadir, "validator_full_node.yaml")),
            "pos_initial_nodes_path": "\'{}\'".format(os.path.join(dirname, "initial_nodes.json")),
            "pos_private_key_path": "'{}'".format(os.path.join(datadir, "blockchain_data", "net_config", "pos_key"))
        }
        local_conf.update(integration_tests.conflux.config.small_local_test_conf)
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
        nodes[from_connection].test_removeNode(nodes[node_num].key, get_peer_addr(nodes[node_num]))
        nodes[node_num].test_removeNode(nodes[from_connection].key, get_peer_addr(nodes[from_connection]))
    except JSONRPCException as e:
        # If this node is disconnected between calculating the peer id
        # and issuing the disconnect, don't worry about it.
        # This avoids a race condition if we're mass-disconnecting peers.
        if e.error['code'] != -29:  # RPC_CLIENT_NODE_NOT_CONNECTED
            raise

    # wait to disconnect
    wait_until(lambda: [peer for peer in nodes[from_connection].test_getPeerInfo() if peer["nodeid"] == nodes[node_num].key] == [], timeout=5)
    wait_until(lambda: [peer for peer in nodes[node_num].test_getPeerInfo() if peer["nodeid"] == nodes[from_connection].key] == [], timeout=5)


def check_handshake(from_connection, target_node_id):
    """
    Check whether node 'from_connection' has already
    added node 'target_node_id' into its peer set.
    """
    peers = from_connection.test_getPeerInfo()
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
    from_connection.test_addNode(key, peer_addr)
    # poll until hello handshake complete to avoid race conditions
    # with transaction relaying
    wait_until(lambda: check_handshake(from_connection, to_connection.key), timeout=timeout)


def sync_blocks(rpc_connections, *, sync_count=True, sync_state=True, wait=1, timeout=60):
    """
    Wait until everybody has the same tip.

    sync_blocks needs to be called with an rpc_connections set that has least
    one node already synced to the latest, stable tip, otherwise there's a
    chance it might return before all nodes are stably synced.
    """
    stop_time = time.time() + timeout
    while time.time() <= stop_time:
        best_hash = [x.best_block_hash() for x in rpc_connections]
        best_executed = [x.cfx_epochNumber("latest_state") if sync_state else 0 for x in rpc_connections]
        block_count = [x.test_getBlockCount() for x in rpc_connections]
        if best_hash.count(best_hash[0]) == len(rpc_connections) \
            and (not sync_state or best_executed.count(best_executed[0]) == len(rpc_connections)) \
                and (not sync_count or block_count.count(block_count[0]) == len(rpc_connections)):
            return
        time.sleep(wait)
    raise AssertionError("Block sync timed out:{}".format("".join(
        "\n  {!r}".format(b) for b in best_hash + best_executed + block_count)))


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
    wait_until(lambda: node.test_getBlockCount() >= count, timeout=timeout)


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
MAX_NODES = 25
# The number of ports to "reserve" for p2p and rpc, each
PORT_RANGE = 100


class PortMin:
    # Must be initialized with a unique integer for each process
    n: int = None


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
    return PortMin.n + n

def rpc_port(n):
    return PortMin.n + MAX_NODES + n*6

def remote_rpc_port(n):
    return rpc_port(n) + 1

def pubsub_port(n):
    return rpc_port(n) + 2

def evm_rpc_port(n):
    return rpc_port(n) + 3

def evm_rpc_ws_port(n):
    return rpc_port(n) + 4

def evm_rpc_port_v2(n):
    return rpc_port(n) + 5

def rpc_url(i, rpchost=None, rpcport=None):
    if rpchost is None:
        # Do not use localhost because our test environment doesn't support
        # IPv6 however the python http library assumes that.
        rpchost = "127.0.0.1"
    if rpcport is None:
        rpcport = rpc_port(i)
    return "http://%s:%d" % (rpchost, int(rpcport))


def pubsub_url(i, evm=False, pubsubhost=None, pubsubport=None):
    if pubsubhost is None:
        # Do not use localhost because our test environment doesn't support
        # IPv6 however the python http library assumes that.
        pubsubhost = "127.0.0.1"
    if pubsubport is None:
        if evm:
            pubsubport = evm_rpc_ws_port(i)
        else:
            pubsubport = pubsub_port(i)
    return "ws://%s:%d" % (pubsubhost, int(pubsubport))


def get_ip_address():
    return [int(i) for i in socket.gethostbyname(socket.gethostname()).split('.')]


def checktx(node, tx_hash):
    return node.cfx_getTransactionReceipt(tx_hash) is not None


def connect_sample_nodes(nodes, log, sample=3, latency_min=0, latency_max=300, timeout=30, max_parallel=500, assert_failure=True):
    """
    Establish connections among nodes with each node having 'sample' outgoing peers.
    It first lets all the nodes link as a loop, then randomly pick 'sample-1'
    outgoing peers for each node.    
    """
    peer = [[] for _ in nodes]
    latencies = [{} for _ in nodes]
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

    for i in range(0, num_nodes, max_parallel):
        batch = range(i, min(i + max_parallel, num_nodes))
        threads = []
        for j in batch:
            t = ConnectThread(nodes, j, peer[j], latencies, log, min_peers=sample)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout)
            if t.is_alive():
                msg = "Node[{}] connect to other nodes timeout in {} seconds".format(t.a, timeout)
                if assert_failure:
                    assert False, msg
                else:
                    log.info(msg)

            if t.failed:
                msg = "connect_sample_nodes failed."
                if assert_failure:
                    assert False, msg
                else:
                    log.info(msg)


def assert_blocks_valid(nodes, blocks):
    for node in nodes:
        for block in blocks:
            r = node.test_getBlockStatus(block)
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
                    self.nodes[self.a].test_addLatency(self.nodes[p].key, self.latencies[self.a][p])
                if len(self.nodes[self.a].test_getPeerInfo()) >= self.min_peers:
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
        raise Exception("deprecated")
        # output = solcx.compile_files([source])
        # if platform == "win32":
        #     source = os.path.abspath(source).replace("\\","/")
        # contract_dict = output[f"{source}:{contract_name}"]
        # if "bin" in contract_dict:
        #     contract_dict["bytecode"] = contract_dict.pop("bin")
        # elif "code" in contract_dict:
        #     contract_dict["bytecode"] = contract_dict.pop("code")
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

# This is a util function to test rpc with block object
def do_rpc_call_test_with_block_object(client: "RpcClient", txs: List, rpc_call: Callable, expected_result_lambda: Callable[..., bool], params: List=[]):
    parent_hash = client.block_by_epoch("latest_mined")['hash']
    
    # generate epoch of 2 block with transactions in each block
    # NOTE: we need `C` to ensure that the top fork is heavier

    #                      ---        ---        ---
    #                  .- | A | <--- | C | <--- | D | <--- ...
    #           ---    |   ---        ---        ---
    # ... <--- | P | <-*                          .
    #           ---    |   ---                    .
    #                  .- | B | <..................
    #                      ---
    
    # all block except for block D is empty

    block_a = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
    block_b = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
    block_c = client.generate_custom_block(parent_hash = block_a, referee = [], txs = [])
    block_d = client.generate_custom_block(parent_hash = block_c, referee = [block_b], txs = txs)

    parent_hash = block_d
    
    # current block_d is not executed
    assert_raises_rpc_error(-32602, None, rpc_call, *params, {
        "blockHash": block_d
    }, err_data_="is not executed")
    
    # cannot find this block
    assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
        "blockHash": "0x{:064x}".format(int(block_d, 16) + 1)
    }, err_data_="block's epoch number is not found")

    for _ in range(5):
        block = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
        parent_hash = block

    assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
        "blockHash": block_b
    })
    assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
        "blockHash": block_b,
        "requirePivot": True
    })
    
    result1 = rpc_call(*params, {
        "blockHash": block_d
    })
    
    result2 = rpc_call(*params, {
        "blockHash": block_b,
        "requirePivot": False
    })
    
    assert(expected_result_lambda(result1))
    assert_equal(result2, result1)

# acct should have cfx
# create a chain of blocks with specified transfer tx with specified num and gas
# return the last block's hash and acct nonce
def generate_blocks_for_base_fee_manipulation(rpc: "RpcClient", acct: Union[CfxLocalAccount, str], block_count=10, tx_per_block=4, gas_per_tx=13500000,initial_parent_hash:str = None) -> Tuple[str, int]:
    if isinstance(acct, str):
        acct = CfxAccount.from_key(acct)
    starting_nonce: int = rpc.get_nonce(acct.hex_address)
    
    if initial_parent_hash is None:
        initial_parent_hash = cast(str, rpc.block_by_epoch("latest_mined")["hash"])

    block_pointer = initial_parent_hash
    for block_count in range(block_count):
        block_pointer, starting_nonce = generate_single_block_for_base_fee_manipulation(rpc, acct, tx_per_block=tx_per_block, gas_per_tx=gas_per_tx,parent_hash=block_pointer, starting_nonce=starting_nonce)

    return block_pointer, starting_nonce + block_count * tx_per_block

def generate_single_block_for_base_fee_manipulation(rpc: "RpcClient", acct: CfxLocalAccount, referee:list[str] =[], tx_per_block=4, gas_per_tx=13500000,parent_hash:str = None, starting_nonce: int = None) -> Tuple[str, int]:
    if starting_nonce is None:
        starting_nonce = cast(int, rpc.get_nonce(acct.hex_address))
    
    if parent_hash is None:
        parent_hash = cast(str, rpc.block_by_epoch("latest_mined")["hash"])

    new_block = rpc.generate_custom_block(
        txs=[
            rpc.new_tx(
                priv_key=acct.key,
                receiver=acct.address,
                gas=gas_per_tx,
                nonce=starting_nonce + i ,
                gas_price=rpc.base_fee_per_gas()*2 # give enough gas price to make the tx valid
            )
            for i in range(tx_per_block)
        ],
        parent_hash=parent_hash,
        referee=referee,
    )
    return new_block, starting_nonce + tx_per_block

# for transactions in either pivot/non-pivot block
# checks priority fee is calculated as expeted
def assert_correct_fee_computation_for_core_tx(rpc: "RpcClient", tx_hash: str, burnt_ratio=0.5):
    def get_gas_charged(rpc: "RpcClient", tx_hash: str) -> int:
        gas_limit = int(rpc.get_tx(tx_hash)["gas"], 16)
        gas_used = int(rpc.get_transaction_receipt(tx_hash)["gasUsed"], 16)
        return max(int(3/4*gas_limit), gas_used)

    receipt = rpc.get_transaction_receipt(tx_hash)
    # The transaction is not executed
    if receipt is None:
        return

    tx_data = rpc.get_tx(tx_hash)
    tx_type = int(tx_data["type"], 16)
    if tx_type == 2:
        # original tx fields
        max_fee_per_gas = int(tx_data["maxFeePerGas"], 16)
        max_priority_fee_per_gas = int(tx_data["maxPriorityFeePerGas"], 16)
    else:
        max_fee_per_gas = int(tx_data["gasPrice"], 16)
        max_priority_fee_per_gas = int(tx_data["gasPrice"], 16)

    effective_gas_price = int(receipt["effectiveGasPrice"], 16)
    transaction_epoch = int(receipt["epochNumber"],16)
    is_in_pivot_block = rpc.block_by_epoch(transaction_epoch)["hash"] == receipt["blockHash"]
    base_fee_per_gas = rpc.base_fee_per_gas(transaction_epoch)
    burnt_fee_per_gas = math.ceil(base_fee_per_gas * burnt_ratio)
    gas_fee = int(receipt["gasFee"], 16)
    burnt_gas_fee = int(receipt["burntGasFee"], 16)
    gas_charged = get_gas_charged(rpc, tx_hash)

    # check gas fee computation
    # print("effective gas price: ", effective_gas_price)
    # print("gas charged: ", get_gas_charged(rpc, tx_hash))
    # print("gas fee", gas_fee)
    
    # check gas fee and burnt gas fee computation
    if receipt["outcomeStatus"] == "0x1": # tx fails because of not enough cash
        assert "NotEnoughCash" in receipt["txExecErrorMsg"]
        # all gas is charged
        assert_equal(rpc.get_balance(tx_data["from"], receipt["epochNumber"]), 0)
        # gas fee less than effective gas price
        assert gas_fee < effective_gas_price*gas_charged
    else:
        assert_equal(gas_fee, effective_gas_price*gas_charged)
        # check burnt fee computation
    assert_equal(burnt_gas_fee, burnt_fee_per_gas*gas_charged)

    # if max_fee_per_gas >= base_fee_per_gas, it shall follow the computation, regardless of transaction in pivot block or not
    if max_fee_per_gas >= base_fee_per_gas:
        priority_fee_per_gas = effective_gas_price - base_fee_per_gas
        # check priority fee computation
        assert_equal(priority_fee_per_gas, min(max_priority_fee_per_gas, max_fee_per_gas - base_fee_per_gas))
    else:
        # max fee per gas should be greater than burnt fee per gas
        assert is_in_pivot_block == False, "Transaction should be in non-pivot block"
        assert max_fee_per_gas >= burnt_fee_per_gas

def assert_tx_exec_error(client: "RpcClient", tx_hash: str, err_msg: str):
    client.wait_for_receipt(tx_hash)
    receipt = client.get_transaction_receipt(tx_hash)
    assert_equal(receipt["txExecErrorMsg"], err_msg)    


InternalContractName = Literal["AdminControl", "SponsorWhitelistControl",
                               "Staking", "ConfluxContext", "PoSRegister", "CrossSpaceCall", "ParamsControl"]

def load_contract_metadata(name: str):
    path = Path(join(dirname(__file__), "..", "..", "..", "tests", "test_contracts", "artifacts"))
    try:
        found_file = next(path.rglob(f"{name}.json"))
        return json.loads(open(found_file, "r").read())
    except StopIteration:
        raise Exception(f"Cannot found contract {name}'s metadata")

