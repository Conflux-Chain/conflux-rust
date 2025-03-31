from integration_tests.conflux.address import hex_to_b32_address
from integration_tests.conflux.config import DEFAULT_PY_TEST_CHAIN_ID


class Filter():
    def __init__(self, from_epoch=None, to_epoch=None, from_block = None, to_block = None, block_hashes = None, address = None, topics = [],
                encode_address=True, networkid=DEFAULT_PY_TEST_CHAIN_ID):
        if encode_address and address is not None:
            if isinstance(address, list):
                base32_address = []
                for a in address:
                    base32_address.append(hex_to_b32_address(a, networkid))
            else:
                base32_address = hex_to_b32_address(address, networkid)
            address = base32_address
        self.fromEpoch = from_epoch
        self.toEpoch = to_epoch
        self.fromBlock = from_block
        self.toBlock = to_block
        self.blockHashes = block_hashes
        self.address = address
        self.topics = topics
