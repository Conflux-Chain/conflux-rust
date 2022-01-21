import rlp
import sys, os

from eth_utils import decode_hex

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from conflux.utils import ec_random_keys, encode_hex, priv_to_pub

priv = "04ac85eea85ee2e3c15fedad6f450d1d8fee06ce95e05f97f064ea28fc8bcbdd"
print(encode_hex(priv_to_pub(decode_hex(priv))))
exit()
NUM_NODES = 2
for _ in range(NUM_NODES):
    pri_key_raw, _ = ec_random_keys()
    pri_key = encode_hex(pri_key_raw)
    pub_key = encode_hex(priv_to_pub(pri_key_raw))
    # print(f"""                {host}:
    #                 index: {i}
    print(f"""
                    net_pri_key: \"{pri_key}\"
                    net_pub_key: \"{pub_key}\"""")
    # i += 1
