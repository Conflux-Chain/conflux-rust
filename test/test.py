#!/usr/bin/env python3
from test_framework.test_node import TestNode
from test_framework.util import *
from time import sleep
import tempfile
import os

PortSeed.n = os.getpid()

tmpdir = tempfile.mkdtemp(prefix="test", dir="/tmp")
nodes = []
for i in range(3):
    initialize_datadir(tmpdir, i)
    nodes.append(
        TestNode(
            i,
            get_datadir_path(tmpdir, i),
            rpchost="localhost",
            confluxd=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "../target/debug/conflux")))

print(tmpdir)
nodes[0].start()
nodes[1].start()
nodes[2].start()
nodes[0].wait_for_rpc_connection()
nodes[1].wait_for_rpc_connection()
nodes[2].wait_for_rpc_connection()
print(nodes[0].getblockcount())
print(nodes[0].getblockcount())
print(nodes[0].getbestblockhash())
print(nodes[1].getblockcount())
print(nodes[1].getbestblockhash())
connect_nodes(nodes[0], 1, nodes[1].key)
connect_nodes(nodes[1], 2, nodes[2].key)
nodes[0].generate(3)
sync_blocks(nodes)
print(nodes[0].getpeerinfo())
print(nodes[1].getblockcount())
print(nodes[2].getbestblockhash())
