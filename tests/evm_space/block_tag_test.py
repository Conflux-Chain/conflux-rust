#!/usr/bin/env python3

# allow imports from parent directory
# source: https://stackoverflow.com/a/11158224
import os, sys
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from base import Web3Base
from test_framework.util import assert_greater_than

class BlockTagTest(Web3Base):

    def run_test(self):
        # super().run_test()
        self.nodes[0].test_generateEmptyBlocks(2000)
        blocks = [
            self.w3.eth.get_block("finalized"),
            self.w3.eth.get_block("safe"),
            self.w3.eth.get_block("latest"),
        ]
        assert_greater_than(blocks[1]["number"], blocks[0]["number"]) # type: ignore
        assert_greater_than(blocks[2]["number"], blocks[1]["number"]) # type: ignore

if __name__ == "__main__":
    BlockTagTest().main()
