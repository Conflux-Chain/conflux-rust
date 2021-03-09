from . import utils
from eth_utils import decode_hex
import rlp

BLANK_NODE = b''
BLANK_ROOT = utils.sha3rlp(b'')
NULL_ROOT = utils.sha3(b'')
# The receipt root of the block itself is KECCAK_EMPTY, however the
# epoch RECEIPT_ROOT is the Merkle Root of the MPT with a single
# key value of (0, KECCAK_EMPTY).
EMPTY_BLOCK_RECEIPT_ROOT = utils.sha3(b'n' + NULL_ROOT * 16 + b'v' + NULL_ROOT)


def state_root(
        snapshot_root = NULL_ROOT,
        intermediate_delta_root = NULL_ROOT,
        delta_root = NULL_ROOT):
    return [snapshot_root, intermediate_delta_root, delta_root]


def precompute_epoch_receipt_root_by_number_of_blocks():
    receipt_root_by_number_of_blocks = []

    # 1 block is a special case for the Receipt Root MPT.
    path_bytes = bytearray()
    path_bytes.extend([128 + 64 + 1, 0])
    epoch_receipt_root_one_block_path_merkle = utils.sha3(
        bytes(path_bytes) + EMPTY_BLOCK_RECEIPT_ROOT)
    receipt_root_by_number_of_blocks.append(
        epoch_receipt_root_one_block_path_merkle
    )
    for number_of_blocks in range(2, 16):
        epoch_receipt_root = utils.sha3(
            b'n' + EMPTY_BLOCK_RECEIPT_ROOT * number_of_blocks \
            + NULL_ROOT * (16 - number_of_blocks))
        receipt_root_by_number_of_blocks.append(epoch_receipt_root)

    return receipt_root_by_number_of_blocks


def compute_transaction_root_for_single_transaction(tx_hash):
    node_hash = utils.sha3(b'n' + NULL_ROOT * 16 + b'v' + tx_hash)
    path_bytes = bytearray()
    path_bytes.extend([128 + 64 + 1, 0])
    return utils.sha3(
        bytes(path_bytes) + node_hash)


UNINITIALIZED_STATE_ROOT = utils.sha3(rlp.encode(state_root()))
EMPTY_EPOCH_RECEIPT_ROOT_BY_NUMBER_OF_BLOCKS = precompute_epoch_receipt_root_by_number_of_blocks()
