#!/usr/bin/env python3
"""Class for conflux node under test"""

import decimal
import errno
from enum import Enum
import http.client
import json
import logging
import os
import re
import subprocess
import tempfile
import shutil

import requests
import time
import urllib.parse

import eth_utils

from integration_tests.conflux.utils import get_nodeid, sha3, encode_int32
from integration_tests.conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from .authproxy import JSONRPCException
from .util import *
from .simple_rpc_proxy import ReceivedErrorResponseError


class FailedToStartError(Exception):
    """Raised when a node fails to start correctly."""


class ErrorMatch(Enum):
    FULL_TEXT = 1
    FULL_REGEX = 2
    PARTIAL_REGEX = 3


class TestNode:
    def __init__(self, index, datadir, rpchost, confluxd, rpc_timeout=None, remote=False, ip=None, user=None,
                 rpcport=None, auto_recovery=False, recovery_timeout=30, chain_id=DEFAULT_PY_TEST_CHAIN_ID,
                 no_pssh=True):
        self.chain_id = chain_id
        self.index = index
        self.datadir = datadir
        self.stdout_dir = os.path.join(self.datadir, "stdout")
        self.stderr_dir = os.path.join(self.datadir, "stderr")
        self.log = os.path.join(self.datadir, "node" + str(index) + ".log")
        self.remote = remote
        self.no_pssh = no_pssh
        self.rpchost = rpchost
        self.auto_recovery = auto_recovery
        self.recovery_timeout = recovery_timeout
        if remote:
            self.ip = ip
            self.user = user
            self.rpcport = rpcport if rpcport is not None else remote_rpc_port(self.index)
        else:
            self.ip = "127.0.0.1"
            self.rpcport = rpc_port(self.index)
            self.ethwsport = evm_rpc_ws_port(self.index)
            self.pubsubport = pubsub_port(self.index)
        self.ethrpcport = evm_rpc_port(self.index)
        self.ethrpcportv2 = evm_rpc_port_v2(self.index)
        self.port = str(p2p_port(index))
        if self.rpchost is None:
            self.rpchost = ip  # + ":" + str(rpc_port(index))
        self.rpc_timeout = CONFLUX_RPC_WAIT_TIMEOUT if rpc_timeout is None else rpc_timeout
        self.binary = confluxd
        self.args = [
            self.binary, "--config",
            os.path.join(self.datadir, "conflux.conf")
        ]

        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc: SimpleRpcProxy = None # type: ignore
        self.ethrpc: SimpleRpcProxy = None
        self.ethrpc_connected = False
        self.log = logging.getLogger('TestFramework.node%d' % index)
        self.cleanup_on_exit = True
        # self.key = "0x" + "0"*125+"{:03d}".format(self.index);
        self.p2ps = []
        if os.path.exists(os.path.join(self.datadir, "pow_sk")):
            self.pow_sk = open(os.path.join(self.datadir, "pow_sk"), "rb").read()
        else:
            self.pow_sk = None

    def _node_msg(self, msg: str) -> str:
        """Return a modified msg that identifies this node by its index as a debugging aid."""
        return "[node %d] %s" % (self.index, msg)

    def _raise_assertion_error(self, msg: str):
        """Raise an AssertionError with msg modified to identify this node."""
        raise AssertionError(self._node_msg(msg))

    def __del__(self):
        # Ensure that we don't leave any bitcoind processes lying around after
        # the test ends
        if self.process and self.cleanup_on_exit:
            # Should only happen on test failure
            # Avoid using logger, as that may have already been shutdown when
            # this destructor is called.
            print(self._node_msg("Cleaning up leftover process"))
            self.process.terminate()
            if self.remote == True:
                cli_kill = "ssh {}@{} killall conflux".format(
                    self.user, self.ip)
                print(self.ip, self.index, subprocess.Popen(
                    cli_kill, shell=True).wait())

    def __getattr__(self, name):
        """Dispatches any unrecognised messages to the RPC connection."""
        assert self.rpc_connected and self.rpc is not None, self._node_msg(
            "Error: no RPC connection")
        if name.startswith("eth_") or name.startswith("parity_"):
            return getattr(self.ethrpc, name)
        else:
            return getattr(self.rpc, name)

    def best_block_hash(self) -> str:
        return self.cfx_getBestBlockHash()

    def start(self, extra_args=None, *, stdout=None, stderr=None, **kwargs):
        # Add a new stdout and stderr file each time conflux is started
        if stderr is None:
            stderr = tempfile.NamedTemporaryFile(
                dir=self.stderr_dir,
                suffix="_" + str(self.index) + "_" + self.ip,
                delete=False)
        if stdout is None:
            stdout = tempfile.NamedTemporaryFile(
                dir=self.stdout_dir,
                suffix="_" + str(self.index) + "_" + self.ip,
                delete=False)
        self.stderr = stderr
        self.stdout = stdout
        if extra_args is not None:
            self.args += extra_args
        if "--public-address" not in self.args:
            self.args += ["--public-address", "{}".format(self.ip)]

        # Delete any existing cookie file -- if such a file exists (eg due to
        # unclean shutdown), it will get overwritten anyway by bitcoind, and
        # potentially interfere with our attempt to authenticate
        delete_cookie_file(self.datadir)
        my_env = os.environ.copy()
        my_env["RUST_BACKTRACE"] = "1"
        if self.remote:
            # If no_pssh is False, we have started the conflux nodes before this, so
            # we can just skip the start here.
            if self.no_pssh:
                ssh_args = '-o "StrictHostKeyChecking no"'
                cli_mkdir = "ssh {} {}@{} mkdir -p {};".format(
                    ssh_args, self.user, self.ip, self.datadir
                )
                cli_conf = "scp {3} -r {0} {1}@{2}:`dirname {0}`;".format(
                    self.datadir, self.user, self.ip, ssh_args
                )
                cli_kill = "ssh {}@{} killall -9 conflux;".format(self.user, self.ip)
                cli_exe = 'ssh {} {}@{} "{} > ~/stdout"'.format(
                    ssh_args,
                    self.user,
                    self.ip,
                    "cd {} && export RUST_BACKTRACE=full && cgexec -g net_cls:limit{} ".format(self.datadir, self.index+1)
                    + " ".join(self.args),
                    )
                print(cli_mkdir + cli_kill + cli_conf + cli_exe)
                self.process = subprocess.Popen(
                    cli_mkdir + cli_kill + cli_conf + cli_exe,
                    stdout=stdout,
                    stderr=stderr,
                    cwd=self.datadir,
                    shell=True,
                    **kwargs,
                    )
        else:
            self.process = subprocess.Popen(
                self.args, stdout=stdout, stderr=stderr, cwd=self.datadir, env=my_env, **kwargs)

        self.running = True
        self.log.debug("conflux started, waiting for RPC to come up")

    def wait_for_rpc_connection(self):
        """Sets up an RPC connection to the conflux process. Returns False if unable to connect."""
        # Poll at a rate of four times per second
        poll_per_s = 4
        for _ in range(poll_per_s * self.rpc_timeout):
            if not self.remote and self.process.poll() is not None:
                raise FailedToStartError(
                    self._node_msg(
                        'conflux exited with status {} during initialization'.
                        format(self.process.returncode)))
            try:
                self.rpc = get_simple_rpc_proxy(
                    rpc_url(self.index, self.rpchost, self.rpcport),
                    node=self,
                    timeout=self.rpc_timeout)
                self.rpc.cfx_getBestBlockHash()
                # If the call to get_best_block_hash() succeeds then the RPC connection is up
                self.rpc_connected = True
                self.url = self.rpc.url
                self.log.debug("RPC successfully started")
                # setup ethrpc
                self.ethrpc = get_simple_rpc_proxy(
                    rpc_url(self.index, self.rpchost, self.ethrpcport),
                    node=self,
                    timeout=self.rpc_timeout)
                self.ethrpc_connected = True
                return
            except requests.exceptions.ConnectionError as e:
                # TODO check if it's ECONNREFUSED`
                pass
            except IOError as e:
                if e.errno != errno.ECONNREFUSED:  # Port not yet open?
                    raise  # unknown IO error
            except JSONRPCException as e:  # Initialization phase
                if e.error['code'] != -28:  # RPC in warmup?
                    raise  # unknown JSON RPC exception
            except ValueError as e:  # cookie file not found and no rpcuser or rpcassword. bitcoind still starting
                if "No RPC credentials" not in str(e):
                    raise
            except ReceivedErrorResponseError as e:
                if e.response.code != 500:
                    raise
            time.sleep(1.0 / poll_per_s)
        self._raise_assertion_error("failed to get RPC proxy: index = {}, ip = {}, rpchost = {}, p2pport={}, rpcport = {}, rpc_url = {}".format(
            self.index, self.ip, self.rpchost, self.port, self.rpcport, rpc_url(self.index, self.rpchost, self.rpcport)
        ))

    def wait_for_recovery(self, phase_to_wait, wait_time):
        self.wait_for_phase(phase_to_wait, wait_time=wait_time)

    def wait_for_phase(self, phases, wait_time=10):
        sleep_time = 0.1
        retry = 0
        max_retry = wait_time / sleep_time

        while self.debug_currentSyncPhase() not in phases and retry <= max_retry:
            time.sleep(0.1)
            retry += 1

        if retry > max_retry:
            current_phase = self.debug_currentSyncPhase()
            raise AssertionError(f"Node did not reach any of {phases} after {wait_time} seconds, current phase is {current_phase}")

    def wait_for_nodeid(self):
        pubkey, x, y = get_nodeid(self)
        self.key = eth_utils.encode_hex(pubkey)
        addr_tmp = bytearray(sha3(encode_int32(x) + encode_int32(y))[12:])
        addr_tmp[0] &= 0x0f
        addr_tmp[0] |= 0x10
        self.addr = addr_tmp
        self.log.debug("Get node {} nodeid {}".format(self.index, self.key))

    def clean_data(self):
        shutil.rmtree(os.path.join(self.datadir, "blockchain_data/blockchain_db"))
        shutil.rmtree(os.path.join(self.datadir, "blockchain_data/storage_db"))
        shutil.rmtree(os.path.join(self.datadir, "pos_db"), ignore_errors=True)
        self.log.info("Cleanup data for node %d", self.index)

    def stop_node(self, expected_stderr='', kill=False, wait=True):
        """Stop the node."""
        if not self.running:
            return
        self.log.debug("Stopping node")
        try:
            if kill:
                self.process.kill()
            else:
                self.process.terminate()
        except http.client.CannotSendRequest:
            self.log.exception("Unable to stop node.")

        if wait:
            self.wait_until_stopped()
        # Check that stderr is as expected
        self.stderr.seek(0)
        stderr = self.stderr.read().decode('utf-8').strip()
        # TODO: Check how to avoid `pthread lock: Invalid argument`.
        if stderr != expected_stderr and stderr != "pthread lock: Invalid argument" and "pthread_mutex_lock" not in stderr:
            if self.return_code is None:
                self.log.info("Process is still running")
            else:
                self.log.info("Process has terminated with code {}".format(self.return_code))
            raise AssertionError("Unexpected stderr {} != {} from {}:{} index={}".format(
                stderr, expected_stderr, self.ip, self.port, self.index))

        self.stdout.close()
        self.stderr.close()

        del self.p2ps[:]

    def is_node_stopped(self):
        """Checks whether the node has stopped.

        Returns True if the node has stopped. False otherwise.
        This method is responsible for freeing resources (self.process)."""
        if not self.running:
            return True
        return_code = self.process.poll()
        if return_code is None:
            return False

        # process has stopped. Assert that it didn't return an error code.
        # assert return_code == 0, self._node_msg(
        #     "Node returned non-zero exit code (%d) when stopping" %
        #     return_code)
        self.running = False
        self.process = None
        self.rpc_connected = False
        self.rpc = None
        self.log.debug("Node stopped")
        self.return_code = return_code
        return True

    def wait_until_stopped(self, timeout=CONFLUX_GRACEFUL_SHUTDOWN_TIMEOUT):
        wait_until(self.is_node_stopped, timeout=timeout)

    def assert_start_raises_init_error(self,
                                       extra_args=None,
                                       expected_msg=None,
                                       match=ErrorMatch.FULL_TEXT,
                                       *args,
                                       **kwargs):
        """Attempt to start the node and expect it to raise an error.

        extra_args: extra arguments to pass through to bitcoind
        expected_msg: regex that stderr should match when bitcoind fails

        Will throw if bitcoind starts without an error.
        Will throw if an expected_msg is provided and it does not match bitcoind's stdout."""
        with tempfile.NamedTemporaryFile(dir=self.stderr_dir, delete=False) as log_stderr, \
                tempfile.NamedTemporaryFile(dir=self.stdout_dir, delete=False) as log_stdout:
            try:
                self.start(
                    extra_args,
                    stdout=log_stdout,
                    stderr=log_stderr,
                    *args,
                    **kwargs)
                self.wait_for_rpc_connection()
                self.stop_node()
                self.wait_until_stopped()
            except FailedToStartError as e:
                self.log.debug('bitcoind failed to start: %s', e)
                self.running = False
                self.process = None
                # Check stderr for expected message
                if expected_msg is not None:
                    log_stderr.seek(0)
                    stderr = log_stderr.read().decode('utf-8').strip()
                    if match == ErrorMatch.PARTIAL_REGEX:
                        if re.search(
                                expected_msg, stderr,
                                flags=re.MULTILINE) is None:
                            self._raise_assertion_error(
                                'Expected message "{}" does not partially match stderr:\n"{}"'.
                                format(expected_msg, stderr))
                    elif match == ErrorMatch.FULL_REGEX:
                        if re.fullmatch(expected_msg, stderr) is None:
                            self._raise_assertion_error(
                                'Expected message "{}" does not fully match stderr:\n"{}"'.
                                format(expected_msg, stderr))
                    elif match == ErrorMatch.FULL_TEXT:
                        if expected_msg != stderr:
                            self._raise_assertion_error(
                                'Expected message "{}" does not fully match stderr:\n"{}"'.
                                format(expected_msg, stderr))
            else:
                if expected_msg is None:
                    assert_msg = "bitcoind should have exited with an error"
                else:
                    assert_msg = "bitcoind should have exited with expected error " + expected_msg
                self._raise_assertion_error(assert_msg)

    def add_p2p_connection(self, p2p_conn, *args, **kwargs):
        """Add a p2p connection to the node.

        This method adds the p2p connection to the self.p2ps list and also
        returns the connection to the caller."""
        if 'dstport' not in kwargs:
            kwargs['dstport'] = int(self.port)
        if 'dstaddr' not in kwargs:
            kwargs['dstaddr'] = self.ip

        p2p_conn.set_chain_id(self.chain_id)

        # if self.ip is not None:
        #     kwargs['dstaddr'] = self.ip
        # print(args, kwargs)
        p2p_conn.peer_connect(*args, **kwargs)()
        self.p2ps.append(p2p_conn)

        return p2p_conn

    @property
    def p2p(self):
        """Return the first p2p connection

        Convenience property - most tests only use a single p2p connection to each
        node, so this saves having to write node.p2ps[0] many times."""
        assert self.p2ps, "No p2p connection"
        return self.p2ps[0]

    def disconnect_p2ps(self):
        """Close all p2p connections to the node."""
        for p in self.p2ps:
            p.peer_disconnect()
        del self.p2ps[:]
