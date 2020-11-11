import sys

sys.path.append("..")

from conflux.rpc import RpcClient
from conflux.config import DEFAULT_PY_TEST_CHAIN_ID


class TestGetStatus(RpcClient):
    def test_get_status(self):
        block_hash = self.generate_block()
        status = self.get_status()
        assert status == {"bestHash": block_hash,
                          "blockNumber": hex(2),
                          "chainId": hex(DEFAULT_PY_TEST_CHAIN_ID),
                          "epochNumber": hex(1),
                          "networkId": hex(DEFAULT_PY_TEST_CHAIN_ID),
                          "pendingTxNumber": hex(0)
                          }
