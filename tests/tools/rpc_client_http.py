#!/usr/bin/env python3

import sys
import json

sys.path.append("..")
from test_framework.util import get_simple_rpc_proxy

""" This tool must be used at current directory.

Usage: python3 rpc_client_http.py [url] method_name [method_args]*

for example:
    - Get epoch number:     python3 rpc_client_http.py cfx_epochNumber
    - Get last mined epoch: python3 rpc_client_http.py cfx_epochNumber latest_mined
    - Specify RPC URL:      python3 rpc_client_http.py http://localhost:8888 cfx_epochNumber

Note, when URL specified, it should be of format http://ip:port."""

assert len(sys.argv) > 1, "Parameter required: [<url: http://ip:port>] <method_name> [<method_args>*]"

rpc_url = "http://localhost:12539"
method_name = sys.argv[1]
method_args = sys.argv[2:]

if sys.argv[1].lower().startswith("http://"):
    rpc_url = sys.argv[1]
    assert len(sys.argv) > 2, "method_name not specified"
    method_name = sys.argv[2]
    method_args = sys.argv[3:]

node=get_simple_rpc_proxy(rpc_url, 3)
method_args = ["\"" + arg + "\"" for arg in method_args]
rpc = "node.{}({})".format(method_name, ", ".join(method_args))
print(json.dumps(eval(rpc), indent=4))