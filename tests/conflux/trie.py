from . import utils
from eth_utils import decode_hex
import rlp

BLANK_NODE = b''
BLANK_ROOT = utils.sha3rlp(b'')
NULL_ROOT = utils.sha3(b'')

def state_root(
        snapshot_root = NULL_ROOT,
        intermediate_delta_root = NULL_ROOT,
        delta_root = NULL_ROOT):
    return [snapshot_root, intermediate_delta_root, delta_root]

UNINITIALIZED_STATE_ROOT = state_root()
