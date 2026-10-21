#!/usr/bin/env python3
from conflux.config import default_config
from invalid_block_sync_test import InvalidBodySyncTest
from test_framework.blocktools import create_transaction


class InvalidPackedGasSyncTest(InvalidBodySyncTest):
    def invalid_tx(self):
        # Passes the per-transaction checks; the body is only rejected by the
        # packed gas limit check, which needs the parent header.
        return create_transaction(gas=default_config["GENESIS_GAS_LIMIT"] + 1)


if __name__ == "__main__":
    InvalidPackedGasSyncTest().main()
