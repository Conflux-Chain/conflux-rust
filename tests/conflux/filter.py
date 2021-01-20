from conflux.address import hex_to_b32_address


class Filter():
    def __init__(self, from_epoch="earliest", to_epoch="latest_state", block_hashes = None, address = None, topics = [],
                 limit = None, encode_address=True):
        if encode_address and address is not None:
            if isinstance(address, list):
                base32_address = []
                for a in address:
                    base32_address.append(hex_to_b32_address(a))
            else:
                base32_address = hex_to_b32_address(address)
            address = base32_address
        self.fromEpoch = from_epoch
        self.toEpoch = to_epoch
        self.blockHashes = block_hashes
        self.address = address
        self.topics = topics
        self.limit = limit
