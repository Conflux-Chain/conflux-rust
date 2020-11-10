#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Base class for RPC testing."""

from conflux.messages import Transactions
from conflux.rpc import RpcClient
from enum import Enum
from http.client import CannotSendRequest
import logging
import argparse
import os
import pdb
import shutil
import sys
import tempfile
import time
from typing import Union
import random

from .authproxy import JSONRPCException
from . import coverage
from .mininode import start_p2p_connection
from .test_node import TestNode
from .util import (
    CONFLUX_RPC_WAIT_TIMEOUT,
    MAX_NODES,
    PortSeed,
    assert_equal,
    check_json_precision,
    checktx,
    connect_nodes,
    connect_sample_nodes,
    disconnect_nodes,
    get_datadir_path,
    initialize_datadir,
    initialize_tg_config,
    p2p_port,
    set_node_times,
    sync_blocks,
    sync_mempools,
    wait_until,
)


class TestStatus(Enum):
    PASSED = 1
    FAILED = 2
    SKIPPED = 3


TEST_EXIT_PASSED = 0
TEST_EXIT_FAILED = 1
TEST_EXIT_SKIPPED = 77


class ConfluxTestFramework:
    """Base class for a bitcoin test script.

    Individual bitcoin test scripts should subclass this class and override the set_test_params() and run_test() methods.

    Individual tests can also override the following methods to customize the test setup:

    - add_options()
    - setup_chain()
    - setup_network()
    - setup_nodes()

    The __init__() and main() methods should not be overridden.

    This class also contains various public and private helper methods."""

    def __init__(self):
        """Sets test framework defaults. Do not override this method. Instead, override the set_test_params() method"""
        self.setup_clean_chain = True
        self.nodes = []
        self.network_thread = None
        self.mocktime = 0
        self.rpc_timewait = CONFLUX_RPC_WAIT_TIMEOUT
        self.supports_cli = False
        self.bind_to_localhost_only = True
        self.conf_parameters = {}
        # The key is file name, and the value is a string as file content.
        self.extra_conf_files = {}
        self.set_test_params()
        self.predicates = {}
        self.snapshot = {}

        assert hasattr(
            self,
            "num_nodes"), "Test must set self.num_nodes in set_test_params()"

    def main(self):
        """Main function. This should not be overridden by the subclass test scripts."""

        parser = argparse.ArgumentParser(usage="%(prog)s [options]")
        parser.add_argument(
            "--nocleanup",
            dest="nocleanup",
            default=False,
            action="store_true",
            help="Leave bitcoinds and test.* datadir on exit or error")
        parser.add_argument(
            "--noshutdown",
            dest="noshutdown",
            default=False,
            action="store_true",
            help="Don't stop bitcoinds after the test execution")
        parser.add_argument(
            "--cachedir",
            dest="cachedir",
            default=os.path.abspath(
                os.path.dirname(os.path.realpath(__file__)) + "/../../cache"),
            help=
            "Directory for caching pregenerated datadirs (default: %(default)s)"
        )
        parser.add_argument(
            "--tmpdir", dest="tmpdir", help="Root directory for datadirs")
        parser.add_argument(
            "-l",
            "--loglevel",
            dest="loglevel",
            default="INFO",
            help=
            "log events at this level and higher to the console. Can be set to DEBUG, INFO, WARNING, ERROR or CRITICAL. Passing --loglevel DEBUG will output all logs to console. Note that logs at all levels are always written to the test_framework.log file in the temporary test directory."
        )
        parser.add_argument(
            "--tracerpc",
            dest="trace_rpc",
            default=False,
            action="store_true",
            help="Print out all RPC calls as they are made")
        parser.add_argument(
            "--portseed",
            dest="port_seed",
            default=os.getpid(),
            type=int,
            help=
            "The seed to use for assigning port numbers (default: current process id)"
        )
        parser.add_argument(
            "--coveragedir",
            dest="coveragedir",
            help="Write tested RPC commands into this directory")
        parser.add_argument(
            "--pdbonfailure",
            dest="pdbonfailure",
            default=False,
            action="store_true",
            help="Attach a python debugger if test fails")
        parser.add_argument(
            "--usecli",
            dest="usecli",
            default=False,
            action="store_true",
            help="use bitcoin-cli instead of RPC for all commands")
        parser.add_argument(
            "--randomseed",
            dest="random_seed",
            type=int,
            help="Set a random seed")
        parser.add_argument(
            "--metrics-report-interval-ms",
            dest="metrics_report_interval_ms",
            default=0,
            type=int)

        parser.add_argument(
            "--conflux-binary",
            dest="conflux",
            default=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "../../target/release/conflux"),
            type=str)
        self.add_options(parser)
        self.options = parser.parse_args()
        self.after_options_parsed()

        PortSeed.n = self.options.port_seed

        check_json_precision()

        self.options.cachedir = os.path.abspath(self.options.cachedir)

        # Set up temp directory and start logging
        if self.options.tmpdir:
            self.options.tmpdir = os.path.abspath(self.options.tmpdir)
            os.makedirs(self.options.tmpdir, exist_ok=True)
        else:
            self.options.tmpdir = os.getenv(
                "CONFLUX_TESTS_LOG_DIR",
                default=tempfile.mkdtemp(prefix="conflux_test_"))
        
        self._start_logging()
        self.log.info("PortSeed.n=" + str(PortSeed.n))

        success = TestStatus.FAILED

        if self.options.random_seed is not None:
            random.seed(self.options.random_seed)

        try:
            if self.options.usecli and not self.supports_cli:
                raise SkipTest(
                    "--usecli specified but test does not support using CLI")
            self.setup_chain()
            self.setup_network()
            self.run_test()
            success = TestStatus.PASSED
        except JSONRPCException as e:
            self.log.exception("JSONRPC error")
        except SkipTest as e:
            self.log.warning("Test Skipped: %s" % e.message)
            success = TestStatus.SKIPPED
        except AssertionError as e:
            self.log.exception("Assertion failed")
        except KeyError as e:
            self.log.exception("Key error")
        except Exception as e:
            self.log.exception("Unexpected exception caught during testing")
        except KeyboardInterrupt as e:
            self.log.warning("Exiting after keyboard interrupt")

        if success == TestStatus.FAILED and self.options.pdbonfailure:
            print(
                "Testcase failed. Attaching python debugger. Enter ? for help")
            pdb.set_trace()

        self.log.debug('Closing down network thread')
        if not self.options.noshutdown:
            self.log.info("Stopping nodes")
            if self.nodes:
                self.stop_nodes()
        else:
            for node in self.nodes:
                node.cleanup_on_exit = False
            self.log.info(
                "Note: bitcoinds were not stopped and may still be running")

        if not self.options.nocleanup and not self.options.noshutdown and success != TestStatus.FAILED:
            self.log.info("Cleaning up {} on exit".format(self.options.tmpdir))
            cleanup_tree_on_exit = True
        else:
            self.log.warning("Not cleaning up dir %s" % self.options.tmpdir)
            cleanup_tree_on_exit = False

        if success == TestStatus.PASSED:
            self.log.info("Tests successful")
            exit_code = TEST_EXIT_PASSED
        elif success == TestStatus.SKIPPED:
            self.log.info("Test skipped")
            exit_code = TEST_EXIT_SKIPPED
        else:
            self.log.error(
                "Test failed. Test logging available at %s/test_framework.log",
                self.options.tmpdir)
            self.log.error("Hint: Call {} '{}' to consolidate all logs".format(
                os.path.normpath(
                    os.path.dirname(os.path.realpath(__file__)) +
                    "/../combine_logs.py"), self.options.tmpdir))
            exit_code = TEST_EXIT_FAILED
        logging.shutdown()
        if cleanup_tree_on_exit:
            shutil.rmtree(self.options.tmpdir)
        sys.exit(exit_code)

    # Methods to override in subclass test scripts.
    def set_test_params(self):
        """Tests must this method to change default values for number of nodes, topology, etc"""
        raise NotImplementedError

    def add_options(self, parser):
        """Override this method to add command-line options to the test"""
        pass

    def after_options_parsed(self):
        if self.options.metrics_report_interval_ms > 0:
            self.conf_parameters["metrics_enabled"] = "true"
            self.conf_parameters["metrics_report_interval_ms"] = str(self.options.metrics_report_interval_ms)

    def setup_chain(self):
        """Override this method to customize blockchain setup"""
        self.log.info("Initializing test directory " + self.options.tmpdir)
        if self.setup_clean_chain:
            self._initialize_chain_clean()
        else:
            self._initialize_chain()

    def setup_network(self):
        """Override this method to customize test network topology"""
        self.setup_nodes()

        # Connect the nodes as a "chain".  This allows us
        # to split the network between nodes 1 and 2 to get
        # two halves that can work on competing chains.
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)
        sync_blocks(self.nodes)

    def setup_nodes(self, binary=None):
        """Override this method to customize test node setup"""
        self.add_nodes(self.num_nodes, binary=binary)
        self.start_nodes()

    def add_nodes(self, num_nodes, rpchost=None, binary=None, auto_recovery=False, recovery_timeout=30, is_consortium=False):
        """Instantiate TestNode objects"""
        if binary is None:
            binary = [self.options.conflux] * num_nodes
        assert_equal(len(binary), num_nodes)
        if is_consortium:
            initialize_tg_config(self.options.tmpdir, num_nodes)
        for i in range(num_nodes):
            node_index = len(self.nodes)
            self.nodes.append(
                TestNode(
                    node_index,
                    get_datadir_path(self.options.tmpdir, node_index),
                    rpchost=rpchost,
                    rpc_timeout=self.rpc_timewait,
                    confluxd=binary[i],
                    auto_recovery=auto_recovery,
                    recovery_timeout=recovery_timeout
                ))

    def add_remote_nodes(self, num_nodes, ip, user, rpchost=None, binary=None, no_pssh=True):
        """Instantiate TestNode objects"""
        if binary is None:
            binary = [self.options.conflux] * num_nodes
        assert_equal(len(binary), num_nodes)
        for i in range(num_nodes):
            self.nodes.append(
                TestNode(
                    i,
                    get_datadir_path(self.options.tmpdir, i),
                    rpchost=rpchost,
                    ip=ip,
                    user=user,
                    rpc_timeout=self.rpc_timewait,
                    confluxd=binary[i],
                    remote=True,
                    no_pssh=no_pssh,
                ))

    def start_node(self, i, extra_args=None, phase_to_wait=("NormalSyncPhase", "CatchUpSyncBlockPhase"), wait_time=30, *args, **kwargs):
        """Start a bitcoind"""

        node = self.nodes[i]

        node.start(extra_args, *args, **kwargs)
        node.wait_for_rpc_connection()
        node.wait_for_nodeid()
        if phase_to_wait is not None:
            node.wait_for_recovery(phase_to_wait, wait_time)

        if self.options.coveragedir is not None:
            coverage.write_all_rpc_commands(self.options.coveragedir, node.rpc)

    def start_nodes(self, extra_args=None, *args, **kwargs):
        """Start multiple bitcoinds"""

        try:
            for i, node in enumerate(self.nodes):
                node.start(extra_args, *args, **kwargs)
            for node in self.nodes:
                node.wait_for_rpc_connection()
                node.wait_for_nodeid()
                node.wait_for_recovery(("NormalSyncPhase", "CatchUpSyncBlockPhase"), 10)
        except:
            # If one node failed to start, stop the others
            self.stop_nodes()
            raise

        if self.options.coveragedir is not None:
            for node in self.nodes:
                coverage.write_all_rpc_commands(self.options.coveragedir,
                                                node.rpc)

    def stop_node(self, i, expected_stderr='', kill=False, wait=True, clean=False):
        """Stop a bitcoind test node"""
        self.nodes[i].stop_node(expected_stderr, kill, wait)
        if clean:
            self.nodes[i].clean_data()

    def stop_nodes(self):
        """Stop multiple bitcoind test nodes"""
        for node in self.nodes:
            # Issue RPC to stop nodes
            node.stop_node()

    def wait_for_node_exit(self, i, timeout):
        self.nodes[i].process.wait(timeout)

    def maybe_restart_node(self, i, stop_probability, clean_probability, wait_time=300):
        if random.random() <= stop_probability:
            self.log.info("stop %s", i)
            clean_data = True if random.random() <= clean_probability else False
            self.stop_node(i, clean=clean_data)
            self.start_node(i, wait_time=wait_time, phase_to_wait=("NormalSyncPhase"))

    # Private helper methods. These should not be accessed by the subclass test scripts.

    def _start_logging(self):
        # Add logger and logging handlers
        self.log = logging.getLogger('TestFramework')
        self.log.setLevel(logging.DEBUG)
        # Create file handler to log all messages
        fh = logging.FileHandler(
            self.options.tmpdir + '/test_framework.log', encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        # Create console handler to log messages to stderr. By default this logs only error messages, but can be configured with --loglevel.
        ch = logging.StreamHandler(sys.stdout)
        # User can provide log level as a number or string (eg DEBUG). loglevel was caught as a string, so try to convert it to an int
        ll = int(self.options.loglevel) if self.options.loglevel.isdigit(
        ) else self.options.loglevel.upper()
        ch.setLevel(ll)
        # Format logs the same as bitcoind's debug.log with microprecision (so log files can be concatenated and sorted)
        formatter = logging.Formatter(
            fmt=
            '%(asctime)s.%(msecs)03d000Z %(name)s (%(levelname)s): %(message)s',
            datefmt='%Y-%m-%dT%H:%M:%S')
        formatter.converter = time.gmtime
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add the handlers to the logger
        self.log.addHandler(fh)
        self.log.addHandler(ch)

        if self.options.trace_rpc:
            rpc_logger = logging.getLogger("ConfluxRPC")
            rpc_logger.setLevel(logging.DEBUG)
            rpc_handler = logging.StreamHandler(sys.stdout)
            rpc_handler.setLevel(logging.DEBUG)
            rpc_logger.addHandler(rpc_handler)

    def _initialize_chain(self):
        """Initialize a pre-mined blockchain for use by the test.

        Create a cache of a 200-block-long chain (with wallet) for MAX_NODES
        Afterward, create num_nodes copies from the cache."""

        assert self.num_nodes <= MAX_NODES
        create_cache = False
        for i in range(MAX_NODES):
            if not os.path.isdir(get_datadir_path(self.options.cachedir, i)):
                create_cache = True
                break

        if create_cache:
            self.log.debug("Creating data directories from cached datadir")

            # find and delete old cache directories if any exist
            for i in range(MAX_NODES):
                if os.path.isdir(get_datadir_path(self.options.cachedir, i)):
                    shutil.rmtree(get_datadir_path(self.options.cachedir, i))

            # Create cache directories, run bitcoinds:
            for i in range(MAX_NODES):
                datadir = initialize_datadir(self.options.cachedir, i, self.extra_conf_files)
                args = [self.options.bitcoind, "-datadir=" + datadir]
                if i > 0:
                    args.append("-connect=127.0.0.1:" + str(p2p_port(0)))
                self.nodes.append(
                    TestNode(
                        i,
                        get_datadir_path(self.options.cachedir, i),
                        extra_conf=["bind=127.0.0.1"],
                        extra_args=[],
                        rpchost=None,
                        rpc_timeout=self.rpc_timewait,
                        bitcoind=self.options.bitcoind,
                        bitcoin_cli=self.options.bitcoincli,
                        mocktime=self.mocktime,
                        coverage_dir=None))
                self.nodes[i].args = args
                self.start_node(i)

            # Wait for RPC connections to be ready
            for node in self.nodes:
                node.wait_for_rpc_connection()

            # Create a 200-block-long chain; each of the 4 first nodes
            # gets 25 mature blocks and 25 immature.
            # Note: To preserve compatibility with older versions of
            # initialize_chain, only 4 nodes will generate coins.
            #
            # blocks are created with timestamps 10 minutes apart
            # starting from 2010 minutes in the past
            self.enable_mocktime()
            block_time = self.mocktime - (201 * 10 * 60)
            for i in range(2):
                for peer in range(4):
                    for j in range(25):
                        set_node_times(self.nodes, block_time)
                        self.nodes[peer].generate_empty_blocks(1)
                        block_time += 10 * 60
                    # Must sync before next peer starts generating blocks
                    sync_blocks(self.nodes)

            # Shut them down, and clean up cache directories:
            self.stop_nodes()
            self.nodes = []
            self.disable_mocktime()

            def cache_path(n, *paths):
                return os.path.join(
                    get_datadir_path(self.options.cachedir, n), "regtest",
                    *paths)

            for i in range(MAX_NODES):
                for entry in os.listdir(cache_path(i)):
                    if entry not in ['wallets', 'chainstate', 'blocks']:
                        os.remove(cache_path(i, entry))

        for i in range(self.num_nodes):
            from_dir = get_datadir_path(self.options.cachedir, i)
            to_dir = get_datadir_path(self.options.tmpdir, i)
            shutil.copytree(from_dir, to_dir)
            initialize_datadir(self.options.tmpdir,
                               i, self.conf_parameters, self.extra_conf_files)  # Overwrite port/rpcport in bitcoin.conf

    def _initialize_chain_clean(self):
        """Initialize empty blockchain for use by the test.

        Create an empty blockchain and num_nodes wallets.
        Useful if a test case wants complete control over initialization."""
        for i in range(self.num_nodes):
            initialize_datadir(self.options.tmpdir, i, self.conf_parameters, self.extra_conf_files)

    def wait_for_tx(self, all_txs, check_status = False):
        for tx in all_txs:
            self.log.debug("Wait for tx to confirm %s", tx.hash_hex())
            for i in range(3):
                try:
                    retry = True
                    while retry:
                        try:
                            wait_until(lambda: checktx(self.nodes[0], tx.hash_hex()), timeout=20)
                            retry = False
                        except CannotSendRequest:
                            time.sleep(0.01)
                    break
                except AssertionError as _:
                    self.nodes[0].p2p.send_protocol_msg(Transactions(transactions=[tx]))
                if i == 2:
                    raise AssertionError("Tx {} not confirmed after 30 seconds".format(tx.hash_hex()))
        # After having optimistic execution, get_receipts may get receipts with not deferred block, these extra blocks
        # ensure that later get_balance can get correct executed balance for all transactions
        client = RpcClient(self.nodes[0])
        for _ in range(5):
            client.generate_block()
        receipts = [client.get_transaction_receipt(tx.hash_hex()) for tx in all_txs]
        self.log.debug("Receipts received: {}".format(receipts))
        if check_status:
            for i in receipts:
                assert_equal(int(i["outcomeStatus"], 0), 0)
        return receipts

class SkipTest(Exception):
    """This exception is raised to skip a test"""

    def __init__(self, message):
        self.message = message

class DefaultConfluxTestFramework(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 8

    def setup_network(self):
        self.log.info("setup nodes ...")
        self.setup_nodes()
        self.log.info("connect peers ...")
        connect_sample_nodes(self.nodes, self.log)
        self.log.info("sync up with blocks among nodes ...")
        sync_blocks(self.nodes)
        self.log.info("start P2P connection ...")
        start_p2p_connection(self.nodes)

class OptionHelper:
    def to_argument_str(arg_name):
        return "--" + str(arg_name).replace("_", "-")

    def parsed_options_to_args(parsed_arg: dict):
        args = []
        for arg_name, value in parsed_arg.items():
            if type(value) is not bool:
                args.append(OptionHelper.to_argument_str(arg_name))
                args.append(str(value))
            elif value:
                # FIXME: This only allows setting boolean to True.
                args.append(OptionHelper.to_argument_str(arg_name))
        return args

    """
    arg_definition is a key-value pair of arg_name and its default value.
    When the default value is set to None, argparse.SUPPRESS is passed to
    argument parser, which means that in the absence of this argument,
    the value is unset, and in this case we assign the type to str.
    
    arg_filter is either None or a set of arg_names to add. By setting 
    arg_filter, A class may use a subset of arg_definition of another 
    class, without changing default value.
    """
    def add_options(
            parser: argparse.ArgumentParser,
            arg_definition: dict,
            arg_filter: Union[None, set, dict] = None):
        for arg_name, default_value in arg_definition.items():
            if arg_filter is None or arg_name in arg_filter:
                try:
                    if default_value is None:
                        parser.add_argument(
                            OptionHelper.to_argument_str(arg_name),
                            dest=arg_name,
                            default=SUPPRESS,
                            type=str
                        )
                    elif type(default_value) is bool:
                        parser.add_argument(
                            OptionHelper.to_argument_str(arg_name),
                            dest=arg_name,
                            action= 'store_false' if default_value else 'store_true',
                        )
                    else:
                        parser.add_argument(
                            OptionHelper.to_argument_str(arg_name),
                            dest=arg_name,
                            default=default_value,
                            type=type(default_value)
                        )
                except argparse.ArgumentError as e:
                    print(f"Ignored argparse error: {e}")

    def conflux_options_to_config(parsed_args: dict, arg_filter: Union[None, set, dict] = None) -> dict:
        conflux_config = {}
        for arg_name, value in parsed_args.items():
            if arg_filter is None or arg_name in arg_filter:
                if type(value) is bool:
                    conflux_config[arg_name] = "true" if value else "false"
                else:
                    conflux_config[arg_name] = repr(value)
        return conflux_config
