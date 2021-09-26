#!/usr/bin/env python3
"""An example functional test
"""
import eth_utils
import os
import sys
import time
from eth_utils import keccak, decode_hex
import eth_abi
from subprocess import check_output


sys.path.insert(1, os.path.join(sys.path[0], '..'))
from conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from conflux.address import hex_to_b32_address
from conflux.filter import Filter
from conflux.rpc import RpcClient
from conflux.utils import int_to_hex, priv_to_addr, parse_as_int
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.blocktools import encode_hex_0x


REGISTER_TOPIC = encode_hex_0x(keccak(b"Register(bytes32,bytes,bytes)"))
INCREASE_STAKE_TOPIC = encode_hex_0x(keccak(b"IncreaseStake(bytes32,uint64)"))

rpc_url = "http://101.132.158.162:12537"
client = RpcClient(node=get_simple_rpc_proxy(rpc_url, timeout=10))
cmd = "./run/pos_config"

voting_power_map = {}
pub_keys_map = {}
last_epoch = client.epoch_number()
print(last_epoch)
for i in range(0, last_epoch, 1000):
    start = i
    end = min(i + 999, last_epoch)
    if end == last_epoch:
        end -= 12
    print(start, end)
    logs = client.get_logs(filter=Filter(from_epoch=int_to_hex(start), to_epoch=int_to_hex(end), address=["0x0888000000000000000000000000000000000005"], networkid=8888))
    print("logs=", logs)
    for log in logs:
        pos_identifier = log["topics"][1]
        if log["topics"][0] == REGISTER_TOPIC:
            bls_pub_key, vrf_pub_key = eth_abi.decode_abi(["bytes", "bytes"], decode_hex(log["data"]))
            pub_keys_map[pos_identifier] = (encode_hex_0x(bls_pub_key), encode_hex_0x(vrf_pub_key))
            print(pub_keys_map[pos_identifier])
        elif log["topics"][0] == INCREASE_STAKE_TOPIC:
            assert pos_identifier in pub_keys_map
            voting_power_map[pos_identifier] = parse_as_int(log["data"])
with open(os.path.join(cmd, "public_keys"), "w") as f:
    for pos_identifier in pub_keys_map.keys():
        f.write(",".join([pub_keys_map[pos_identifier][0][2:], pub_keys_map[pos_identifier][1][2:], str(voting_power_map[pos_identifier])]) + "\n")
tg_config_gen = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../target/release/pos-genesis-tool")
check_output([tg_config_gen, "frompub", "public_keys"], cwd=cmd)
waypoint = open(os.path.join(cmd, "waypoint_config"), "r").readlines()[0]
conf_file = open(os.path.join(cmd, "pos_config.yaml"), "w")
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
  file: ./pos.log
  level: DEBUG
#storage:
  #dir: ./pos_db/db
""")
os.remove(os.path.join(cmd, "public_keys"))
os.remove(os.path.join(cmd, "waypoint_config"))
