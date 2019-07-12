class Filter():
    def __init__(self, from_epoch, to_epoch, block_hashes = None, address = None, topics = [], limit = None):
        self.fromEpoch = from_epoch
        self.toEpoch = to_epoch
        self.blockHashes = block_hashes
        self.address = address
        self.topics = topics
        self.limit = limit
