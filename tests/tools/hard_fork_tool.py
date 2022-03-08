#!/usr/bin/env python3
"""An example functional test
"""
import eth_utils
import os
import sys
import time
from eth_utils import keccak, decode_hex
import eth_abi
import collections
from subprocess import check_output


sys.path.insert(1, os.path.join(sys.path[0], '..'))
from conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from conflux.address import hex_to_b32_address
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr, parse_as_int, encode_hex
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.blocktools import encode_hex_0x


rpc_url = "https://main.confluxrpc.com"
# set to bitcoin block hash after block number 92751800
bitcoin_block_hash = "000000000000000000075ae6d38f9b2eeab602c61c30d506b480ef1ac7c94033"
start_block_number = 92060600
end_block_number = 92751800

REGISTER_TOPIC = encode_hex_0x(keccak(b"Register(bytes32,bytes,bytes)"))
INCREASE_STAKE_TOPIC = encode_hex_0x(keccak(b"IncreaseStake(bytes32,uint64)"))
client = RpcClient(node=get_simple_rpc_proxy(rpc_url, timeout=10))
cwd = "./run/pos_config"

voting_power_map = collections.defaultdict(lambda: 0)
pub_keys_map = {}
for i in range(start_block_number, end_block_number + 1, 1000):
    start = i
    end = min(i + 999, end_block_number + 1)
    print(start, end)
    logs = client.get_logs(filter=Filter(from_block=hex(start), to_block=hex(end), address=["0x0888000000000000000000000000000000000005"], networkid=1029))
    print("logs=", logs)
    for log in logs:
        pos_identifier = log["topics"][1]
        if log["topics"][0] == REGISTER_TOPIC:
            bls_pub_key, vrf_pub_key = eth_abi.decode_abi(["bytes", "bytes"], decode_hex(log["data"]))
            pub_keys_map[pos_identifier] = (encode_hex_0x(bls_pub_key), encode_hex_0x(vrf_pub_key))
            print(pub_keys_map[pos_identifier])
        elif log["topics"][0] == INCREASE_STAKE_TOPIC:
            assert pos_identifier in pub_keys_map
            voting_power_map[pos_identifier] += parse_as_int(log["data"])
with open(os.path.join(cwd, "public_keys"), "w") as f:
    for pos_identifier in pub_keys_map.keys():
        f.write(",".join([pub_keys_map[pos_identifier][0][2:], pub_keys_map[pos_identifier][1][2:], str(voting_power_map[pos_identifier])]) + "\n")
cfx_block_hash = client.block_by_block_number(hex(end_block_number))["hash"]
initial_seed = encode_hex(keccak(hexstr=cfx_block_hash[2:]+bitcoin_block_hash))
tg_config_gen = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../target/release/pos-genesis-tool")
check_output([tg_config_gen, "frompub", "--initial-seed={}".format(initial_seed),"public_keys"], cwd=cwd)
waypoint = open(os.path.join(cwd, "waypoint_config"), "r").readlines()[0]
conf_file = open(os.path.join(cwd, "pos_config.yaml"), "w")
conf_file.write(f"""
base:
  #data_dir: ./pos_db
  role: validator
  waypoint:
    from_config: {waypoint}
consensus:
  round_initial_timeout_ms: 60000
  safety_rules:
    service:
      type: local
execution:
  genesis_file_location: ./genesis_file
logger:
  file: ./log/pos.log
  level: INFO
#storage:
  #dir: ./pos_db/db
""")
os.remove(os.path.join(cwd, "public_keys"))
os.remove(os.path.join(cwd, "waypoint_config"))
