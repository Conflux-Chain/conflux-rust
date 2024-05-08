from web3 import Web3

from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

from os.path import dirname, realpath, join


EVM_CHAIN_ID = 12
ZERO_HASH = "0" * 64

class CIP98Test(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.conf_parameters["evm_chain_id"] = str(EVM_CHAIN_ID)
        self.conf_parameters["evm_transaction_block_ratio"] = str(1)
        self.conf_parameters["dao_vote_transition_number"] = "100"
        # Disable CIP-133 on test
        self.conf_parameters["next_hardfork_transition_number"] = str(9999999)
        self.conf_parameters["next_hardfork_transition_height"] = str(9999999)

    def run_test(self):
        rpc = self.nodes[0].rpc
        client = RpcClient(self.nodes[0])
        ip = self.nodes[0].ip
        port = self.nodes[0].ethrpcport
        w3 = Web3(Web3.HTTPProvider(f'http://{ip}:{port}/'))
        start_p2p_connection(self.nodes)
        priv = default_config["GENESIS_PRI_KEY"]
        account = w3.eth.account.privateKeyToAccount(priv)

        # Create forks to make block number != epoch number
        client.generate_block()
        time.sleep(0.2)
        block = rpc.cfx_getBlockByEpochNumber("latest_mined", False)
        for i in range(5):
            client.generate_block_with_parent(block["hash"], pos_reference=block["posReference"])
        client.generate_block()
        time.sleep(0.2)
        block = rpc.cfx_getBlockByEpochNumber("latest_mined", False)
        assert_ne(int(block["blockNumber"], 16), int(block["epochNumber"], 16))

        # Deploy contract for test
        hash_contract_bytecode_path = join(dirname(realpath(__file__)),
                                           *"contracts/cip98_test.bytecode".split("/"))
        bytecode = open(hash_contract_bytecode_path, "r").read()
        hash_contract_abi_path = join(dirname(realpath(__file__)),
                                      *"contracts/cip98_test.json".split("/"))
        abi = json.loads(open(hash_contract_abi_path, "r").read())
        signed = account.signTransaction(dict(data=bytecode, gas=200000, nonce=0, gasPrice=1, chainId=EVM_CHAIN_ID))
        w3.eth.sendRawTransaction(signed["rawTransaction"])
        client.generate_blocks(20, 1)
        receipt = w3.eth.waitForTransactionReceipt(signed["hash"])
        contract = w3.eth.contract(abi=abi, address=receipt["contractAddress"])

        assert_equal(encode_hex(contract.functions.query().call()), ZERO_HASH)

        client.generate_blocks(100)
        wait_until(lambda: int(rpc.cfx_getBlockByEpochNumber("latest_state", False)["blockNumber"], 16) > 100)
        assert_ne(encode_hex(contract.functions.query().call()), ZERO_HASH)


if __name__ == "__main__":
    CIP98Test().main()
