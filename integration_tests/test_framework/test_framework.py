#!/usr/bin/env python3
# Copyright (c) 2014-2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Base class for RPC testing."""
import pytest
from typing import List, Literal, Union, Any, cast, Type
from dataclasses import dataclass
from integration_tests.conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from integration_tests.conflux.messages import Transactions
from integration_tests.conflux.rpc import RpcClient, default_config
from enum import Enum
from http.client import CannotSendRequest
import logging
import os
import pdb
import shutil
import sys
import tempfile
import time
import random
from functools import cached_property
from conflux_web3 import Web3 as CWeb3
from conflux_web3.middleware.base import ConfluxWeb3Middleware
from conflux_web3._utils.rpc_abi import (
    RPC
)
from conflux_web3.contract import ConfluxContract
from web3 import Web3
from web3.middleware import Web3Middleware
from web3.middleware.signing import SignAndSendRawMiddlewareBuilder
from web3.types import RPCEndpoint
from cfx_account import Account as CoreAccount
from eth_account import Account

from .authproxy import JSONRPCException
from . import coverage
from .mininode import start_p2p_connection, NetworkThread
from .test_node import TestNode
from .util import (
    CONFLUX_RPC_WAIT_TIMEOUT,
    MAX_NODES,
    PortMin,
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
    assert_tx_exec_error,
    load_contract_metadata,
    InternalContractName,
)
from .block_gen_thread import BlockGenThread

class TestStatus(Enum):
    PASSED = 1
    FAILED = 2
    SKIPPED = 3


TEST_EXIT_PASSED = 0
TEST_EXIT_FAILED = 1
TEST_EXIT_SKIPPED = 77

Web3NotSetupError = ValueError("w3 is not initialized, please call self.setup_w3() first")

@dataclass
class FrameworkOptions:
    nocleanup: bool  # leave bitcoinds and test.* datadir on exit or error
    noshutdown: bool  # don't stop bitcoinds after the test execution
    cachedir: str  # directory for caching pregenerated datadirs
    tmpdir: str  # root directory for datadirs
    loglevel: str  # log events at this level and higher to the console
    trace_rpc: bool  # print out all RPC calls as they are made
    # never used
    port_min: int  # port range for the test nodes, if set to 0, use the port_min fixture
    # port_seed: int  # the seed to use for assigning port numbers
    coveragedir: str  # write tested RPC commands into this directory
    pdbonfailure: bool  # attach a python debugger if test fails
    usecli: bool  # use bitcoin-cli instead of RPC for all commands
    random_seed: int  # set a random seed
    metrics_report_interval_ms: int  # report metrics interval in milliseconds
    conflux: str  # path to conflux binary
    

class ConfluxTestFramework:
    """Base class for a bitcoin test script.

    Individual bitcoin test scripts should subclass this class and override the set_test_params() and run_test() methods.

    Individual tests can also override the following methods to customize the test setup:

    - setup_chain()
    - setup_network()
    - setup_nodes()

    The __init__() and main() methods should not be overridden.

    This class also contains various public and private helper methods."""

    _cw3: Union[CWeb3, None] = None
    _ew3: Union[Web3, None] = None
    num_nodes: int

    def __init__(self, port_min: int, additional_secrets: int=0, *, options: FrameworkOptions):
        """Sets test framework defaults. Do not override this method. Instead, override the set_test_params() method"""
        self.core_secrets: list[str] = [default_config["GENESIS_PRI_KEY"].hex()]  # type: ignore
        self.evm_secrets: list[str] = [default_config["GENESIS_PRI_KEY_2"].hex()]  # type: ignore
        self._add_genesis_secrets(additional_secrets)
        self.options = options
        self.port_min = self.options.port_min or port_min # if port_min is set to 0, use the port_min fixture
        self.setup_clean_chain = True
        self.nodes: list[TestNode] = []
        self.mocktime = 0
        self.rpc_timewait = CONFLUX_RPC_WAIT_TIMEOUT
        self.supports_cli = False
        self.bind_to_localhost_only = True
        self.conf_parameters = {}
        self.pos_parameters = {"round_time_ms": 1000}
        # The key is file name, and the value is a string as file content.
        self.extra_conf_files = {}
        self.set_test_params()
        self.predicates = {}
        self.snapshot = {}

        assert hasattr(
            self,
            "num_nodes"), "Test must set self.num_nodes in set_test_params()"


        
        PortMin.n = self.port_min # This line sets the port range for the test nodes

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
        
        self.log.debug('Setting up network thread')
        self.network_thread = NetworkThread()
        self.network_thread.start()

        if self.options.random_seed is not None:
            random.seed(self.options.random_seed)

        self.after_options_parsed()

        if self.options.usecli and not self.supports_cli:
            raise SkipTest(
                "--usecli specified but test does not support using CLI")
        self.setup_chain()
        self.setup_network()
        self.before_test()

    def teardown(self, request: pytest.FixtureRequest):
        success = TestStatus.PASSED
        if request.session.testsfailed > 0:
            success = TestStatus.FAILED
            self.log.exception(f"{request.session.testsfailed} tests failed")

        self.log.debug('Closing down network thread')
        self.network_thread.close()

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
        else:
            self.log.error(
                "Test failed. Test logging available at %s/test_framework.log",
                self.options.tmpdir)
            self.log.error("Hint: Call {} '{}' to consolidate all logs".format(
                os.path.normpath(
                    os.path.dirname(os.path.realpath(__file__)) +
                    "/../combine_logs.py"), self.options.tmpdir))
        handlers = self.log.handlers[:]
        for handler in handlers:
            self.log.removeHandler(handler)
            handler.close()
        logging.shutdown()
        if cleanup_tree_on_exit:
            shutil.rmtree(self.options.tmpdir)
            

    def _add_genesis_secrets(
        self,
        additional_secrets: int,
        space: Union[List[Literal["evm", "core"]], Literal["evm", "core"]]=["evm", "core"]
    ):
        """
        Add random secrets to `self.core_secrets` and `self.evm_secrets`.
        When node starts, `self.core_secrets` and `self.evm_secrets` will be used
        to generate genesis account for both EVM and Core
        each with 10000 CFX (10^21 drip).
        
        The generated accounts can be used from `self.core_accounts` or `self.evm_accounts`.
        """
        for _ in range(additional_secrets):
            if "evm" in space or "evm" == space:
                self.evm_secrets.append(Account.create().key.hex())
            if "core" in space or "core" == space:
                self.core_secrets.append(Account.create().key.hex())

    @cached_property
    def client(self) -> RpcClient:
        """Get the RPC client, using the first node.
        The RPC client is 

        Returns:
            RpcClient: used to send RPC requests to the node.
                For example, self.client.cfx_getBalance(...) or self.client.eth_getBalance(...)
                It should be noticed that the parameters are usually not formatted. 
                Certain methods also provide formatted parameters, for example, self.client.epoch_number().
                Please check the source code for more details.
        """
        return RpcClient(self.nodes[0])

    @property
    def cw3(self) -> CWeb3:
        """Get the Conflux Web3 instance, initialized by self.setup_w3().

        Raises:
            Web3NotSetupError: If the Web3 instance is not initialized.

        Returns:
            CWeb3: The Conflux Web3 instance.
        """
        if self._cw3 is None:
            raise Web3NotSetupError
        return self._cw3
    
    @property
    def ew3(self) -> Web3:
        """Get the EVM Web3 instance, initialized by self.setup_w3().

        Raises:
            Web3NotSetupError: If the Web3 instance is not initialized.

        Returns:
            Web3: The EVM Web3 instance.
        """
        if self._ew3 is None:
            raise Web3NotSetupError
        return self._ew3
    
    @property
    def cfx(self):
        if self._cw3 is None:
            raise Web3NotSetupError
        return self._cw3.cfx
    
    @property
    def eth(self):
        if self._ew3 is None:
            raise Web3NotSetupError
        return self._ew3.eth
   
    @property
    def core_accounts(self):
        """
        Get the core space genesis accounts.
        Amount can be added by `self._add_genesis_secrets(additional_secrets_count)`.
        """
        return [CoreAccount.from_key(key, network_id=DEFAULT_PY_TEST_CHAIN_ID) for key in self.core_secrets]
    
    @property
    def evm_accounts(self):
        """
        Get the eSpace genesis accounts.
        Amount can be added by `self._add_genesis_secrets(additional_secrets_count)`.
        """
        return [Account.from_key(key) for key in self.evm_secrets]

    # Methods to override in subclass test scripts.
    def set_test_params(self):
        """Tests must this method to change default values for number of nodes, topology, etc"""
        raise NotImplementedError

    def add_options(self, parser):
        raise DeprecationWarning("add_options is deprecated in new test framework")

    def after_options_parsed(self):
        if self.options.metrics_report_interval_ms > 0:
            self.conf_parameters["metrics_enabled"] = "true"
            self.conf_parameters["metrics_report_interval_ms"] = str(self.options.metrics_report_interval_ms)

    def setup_chain(self):
        """Override this method to customize blockchain setup"""
        self.log.info("Initializing test directory " + self.options.tmpdir)
        self._initialize_chain_clean()

    def setup_network(self):
        """Override this method to customize test network topology"""
        self.setup_nodes()

        # Connect the nodes as a "chain".  This allows us
        # to split the network between nodes 1 and 2 to get
        # two halves that can work on competing chains.
        for i in range(self.num_nodes - 1):
            connect_nodes(self.nodes, i, i + 1)
        sync_blocks(self.nodes)

    def setup_nodes(self, genesis_nodes=None, binary=None, is_consortium=True):
        """Override this method to customize test node setup"""
        self.add_nodes(self.num_nodes, genesis_nodes=genesis_nodes, binary=binary, is_consortium=is_consortium)
        self.start_nodes()
    
    def setup_w3(self):
        """Setup w3 and ew3 for EVM and Conflux.
        This method should be called before any test.
        Use self.cw3 and self.ew3 to access the web3 instances.
        Use self.cw3.cfx and self.ew3.eth to access the Conflux and EVM RPC clients.
        """
        client = RpcClient(self.nodes[0])
        log = self.log
        self._cw3 = CWeb3(CWeb3.HTTPProvider(f'http://{self.nodes[0].ip}:{self.nodes[0].rpcport}/'))
        self._ew3 = Web3(Web3.HTTPProvider(f'http://{self.nodes[0].ip}:{self.nodes[0].ethrpcportv2}/'))
        self._legacy_ew3 = Web3(Web3.HTTPProvider(f'http://{self.nodes[0].ip}:{self.nodes[0].ethrpcport}/'))

        self.cw3.wallet.add_accounts(self.core_accounts)
        self.cw3.cfx.default_account = self.core_accounts[0].address
        
        self.ew3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(self.evm_secrets)) # type: ignore
        self.eth.default_account = self.evm_accounts[0].address
        
        self._legacy_ew3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(self.evm_secrets)) # type: ignore
        self._legacy_ew3.eth.default_account = self.evm_accounts[0].address
        
        class TestNodeMiddleware(ConfluxWeb3Middleware):
            def request_processor(self, method: RPCEndpoint, params: Any) -> Any:
                if method == RPC.cfx_sendRawTransaction or method == RPC.cfx_sendTransaction or method == "eth_sendRawTransaction" or method == "eth_sendTransaction":
                    client.node.wait_for_phase(["NormalSyncPhase"])
                    
                if method == RPC.cfx_maxPriorityFeePerGas or method == "eth_maxPriorityFeePerGas":
                    if client.epoch_number() == 0:
                        # enable cfx_maxPriorityFeePerGas
                        # or Error(Epoch number larger than the current pivot chain tip) would be raised
                        client.generate_blocks_to_state(num_txs=1)
                return super().request_processor(method, params)

            def response_processor(self, method: RPCEndpoint, response: Any):
                if method == RPC.cfx_getTransactionReceipt or method == "eth_getTransactionReceipt":
                    if "result" in response and response["result"] is None:
                        log.debug("Auto generate 5 blocks because did not get tx receipt")
                        client.generate_blocks_to_state(num_txs=1)  # why num_txs=1?
                return response
        
        self.cw3.middleware_onion.add(TestNodeMiddleware)
        self.ew3.middleware_onion.add(TestNodeMiddleware)
        self._legacy_ew3.middleware_onion.add(TestNodeMiddleware)

    def add_nodes(self, num_nodes, genesis_nodes=None, rpchost=None, binary=None, auto_recovery=False,
                  recovery_timeout=30, is_consortium=True):
        """Instantiate TestNode objects"""
        if binary is None:
            binary = [self.options.conflux] * num_nodes
        assert_equal(len(binary), num_nodes)
        if genesis_nodes is None:
            genesis_nodes = num_nodes
        if is_consortium:
            initialize_tg_config(self.options.tmpdir, num_nodes, genesis_nodes, DEFAULT_PY_TEST_CHAIN_ID,
                                 start_index=len(self.nodes), pos_round_time_ms=self.pos_parameters["round_time_ms"], conflux_binary_path=self.options.conflux)
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

    def start_node(self, i:int, extra_args=None, phase_to_wait=["NormalSyncPhase"], wait_time=30, *args, **kwargs):
        """Start a bitcoind"""

        node = self.nodes[i]

        node.start(extra_args, *args, **kwargs)
        node.wait_for_rpc_connection()
        node.wait_for_nodeid()
        # try:
        #     node.test_posStart()
        # except Exception as e:
        #     print(e)
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
                node.wait_for_recovery(["NormalSyncPhase"], 10)
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

    def _initialize_chain_clean(self):
        """Initialize empty blockchain for use by the test.

        Create an empty blockchain and num_nodes wallets.
        Useful if a test case wants complete control over initialization."""

        for i in range(self.num_nodes):
            initialize_datadir(self.options.tmpdir, i, self.port_min, self.conf_parameters,
                               self.extra_conf_files, self.core_secrets, self.evm_secrets)
            
    def before_test(self):
        self.setup_w3()

    # wait for core space tx
    def wait_for_tx(self, all_txs, check_status=False):
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
                if int(i["outcomeStatus"], 0) != 0:
                    raise AssertionError("Receipt states the execution failes: {}".format(i))
        return receipts   

    def start_block_gen(self):
        BlockGenThread(self.nodes, self.log).start()
        
    def cfx_contract(self, name) -> Type[ConfluxContract]:
        metadata = load_contract_metadata(name)
        return self.cfx.contract(
            abi=metadata["abi"], bytecode=metadata["bytecode"])
    
    def evm_contract(self, name):
        metadata = load_contract_metadata(name)
        return self.eth.contract(
            abi=metadata["abi"], bytecode=metadata["bytecode"])

    def internal_contract(self, name: InternalContractName):
        return self.cfx.contract(name=name, with_deployment_info=True)

    def deploy_contract(self, name, transact_args = {}) -> ConfluxContract:
        tx_hash = self.cfx_contract(name).constructor().transact(transact_args)
        receipt = tx_hash.executed(timeout=30)
        return self.cfx_contract(name)(cast(str, receipt["contractCreated"]))
    
    def deploy_evm_contract(self,name,transact_args = {}):
        tx_hash = self.evm_contract(name).constructor().transact(transact_args)
        receipt = self.eth.wait_for_transaction_receipt(tx_hash)
        return self.evm_contract(name)(receipt["contractAddress"])

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
