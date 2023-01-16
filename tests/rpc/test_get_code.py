import eth_utils
import sys
import os
sys.path.append("..")

from conflux.rpc import RpcClient
from conflux.utils import sha3 as keccak, parse_as_int
from jsonrpcclient.exceptions import ReceivedErrorResponseError
from test_framework.blocktools import encode_hex_0x
from test_framework.util import assert_equal, test_rpc_call_with_block_object, assert_raises_rpc_error

REVERT_MESSAGE_CONTRACT_PATH = "../contracts/revert_message.dat"

class TestGetCode(RpcClient):

    def test_get_code(self):
        # test simple storage contract with default value (5)
        data = "0x608060405234801561001057600080fd5b50600560008190555060e6806100276000396000f3fe6080604052600436106043576000357c01000000000000000000000000000000000000000000000000000000009004806360fe47b11460485780636d4ce63c14607f575b600080fd5b348015605357600080fd5b50607d60048036036020811015606857600080fd5b810190808035906020019092919050505060a7565b005b348015608a57600080fd5b50609160b1565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea165627a7a72305820b5180d95fdc3813028ed47f62c7cdf708b76c0db094043f533b42a430d313e150029"
        tx = self.new_contract_tx("", data, storage_limit=200000)
        client = self
        parent_hash = client.block_by_epoch("latest_mined")['hash']
        rpc_call = self.get_code
        txs = [tx]
        expected_result_lambda = lambda x: x != "0x"
    
        # generate epoch of 2 block with transactions in each block
        # NOTE: we need `C` to ensure that the top fork is heavier

        #                      ---        ---        ---
        #                  .- | A | <--- | C | <--- | D | <--- ...
        #           ---    |   ---        ---        ---
        # ... <--- | P | <-*                          .
        #           ---    |   ---                    .
        #                  .- | B | <..................
        #                      ---

        # all block except for block D is empty

        block_a = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
        block_b = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
        block_c = client.generate_custom_block(parent_hash = block_a, referee = [], txs = [])
        block_d = client.generate_custom_block(parent_hash = block_c, referee = [block_b], txs = txs)

        parent_hash = block_d
        
        for _ in range(5):
            block = client.generate_custom_block(parent_hash = parent_hash, referee = [], txs = [])
            parent_hash = block
            
        contract_addr = self.get_tx(tx.hash_hex())["contractCreated"]
        params = [contract_addr]
        
        assert_raises_rpc_error(-32602, None, rpc_call, *params, {
            "blockHash": parent_hash
        }, err_data_="is not executed")
        
        # cannot find this block
        assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
            "blockHash": hex(int(block_d, 16) + 1)
        }, err_data_="block's epoch number is not found")

        assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
            "blockHash": block_b
        })
        assert_raises_rpc_error(-32602, "Invalid parameters: epoch parameter", rpc_call, *params, {
            "blockHash": block_b,
            "requirePivot": True
        })

        result1 = rpc_call(*params, {
            "blockHash": block_d
        })
        result1 = rpc_call(*params, {
            "blockHash": block_d
        })

        result2 = rpc_call(*params, {
            "blockHash": block_b,
            "requirePivot": False
        })

        assert(expected_result_lambda(result1))
        assert_equal(result2, result1)
