#!/usr/bin/env python3

import sys
import json

sys.path.append("..")
from test_framework.util import get_rpc_proxy

assert len(sys.argv) > 1, "Parameter required: [<url: http://ip:port>] <method_name> [<method_args>*]"

rpc_url = "http://localhost:12537"
method_name = sys.argv[1]
method_args = sys.argv[2:]

if sys.argv[1].startswith("http://"):
    rpc_url = sys.argv[1]
    assert len(sys.argv) > 2, "method_name not specified"
    method_name = sys.argv[2]
    method_args = sys.argv[3:]

node=get_rpc_proxy(rpc_url, 3)
method_args = ["\"" + arg + "\"" for arg in method_args]
rpc = "node.{}({})".format(method_name, ", ".join(method_args))
print(json.dumps(eval(rpc), indent=4))