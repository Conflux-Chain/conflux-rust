import eth_utils
from eth_utils import decode_hex

from .address_utils import *
from integration_tests.conflux.config import DEFAULT_PY_TEST_CHAIN_ID
from integration_tests.conflux.utils import encode_hex

MAINNET_PREFIX = "cfx"
TESTNET_PREFIX = "cfxtest"
OTHER_NET_PREFIX = "net"
VERSION_BYTE = 0x00
MAINNET_NETWORK_ID = 1029
TESTNET_NETWORK_ID = 1
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def network_id_to_prefix(network_id):
    if network_id == TESTNET_NETWORK_ID:
        return TESTNET_PREFIX
    elif network_id == MAINNET_NETWORK_ID:
        return MAINNET_PREFIX
    else:
        return OTHER_NET_PREFIX + str(network_id)


def prefix_to_network_id(prefix):
    if prefix == MAINNET_PREFIX:
        return MAINNET_NETWORK_ID
    elif prefix == TESTNET_PREFIX:
        return TESTNET_NETWORK_ID
    elif prefix[:3] == OTHER_NET_PREFIX and int(prefix[3:]) not in [TESTNET_NETWORK_ID, MAINNET_NETWORK_ID]:
        return int(prefix[3:])
    else:
        assert False, "Invalid address prefix"


def encode_b32_address(addr, network_id=DEFAULT_PY_TEST_CHAIN_ID):
    payload = convertbits([VERSION_BYTE] + list(addr), 8, 5)
    prefix = network_id_to_prefix(network_id)
    checksum = calculate_checksum(prefix, payload)
    return "{}:{}".format(prefix, b32encode(payload + checksum))


# Note: This function does not return network_id on purpose, because in python tests it is DEFAULT_PY_TEST_CHAIN_ID
# while the prefix is `cfx`.
def decode_b32_address(b32_addr):
    b32_addr = b32_addr.lower()
    addr_array = b32_addr.split(":")
    prefix = addr_array[0]
    payload_and_checksum = addr_array[-1]
    assert len(payload_and_checksum) == 42
    payload_and_checksum_raw = b32decode(payload_and_checksum)
    if not verify_checksum(prefix, payload_and_checksum_raw):
        assert False, "Invalid address checksum"
    # Remove checksum bits
    payload_raw = payload_and_checksum_raw[:-CHECKSUM_SIZE]
    # Remove version byte
    address_bytes = bytes(convertbits(payload_raw, 5, 8, pad=False))[1:]
    return address_bytes


def b32_address_to_hex(addr):
    return eth_utils.encode_hex(decode_b32_address(addr))


def hex_to_b32_address(addr, network_id=DEFAULT_PY_TEST_CHAIN_ID):
    return encode_b32_address(decode_hex(addr), network_id)

