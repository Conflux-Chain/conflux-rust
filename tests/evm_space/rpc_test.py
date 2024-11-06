from base import Web3Base
from conflux.config import default_config
from test_framework.util import *
from web3 import Web3

toHex = Web3.toHex

class EspaceRpcTest(Web3Base):

    def run_test(self):
        self.cfxPrivkey = default_config['GENESIS_PRI_KEY']
        self.cfxAccount = self.rpc.GENESIS_ADDR
        print(f'Using Conflux account {self.cfxAccount}')

        self.evmAccount = self.w3.eth.account.privateKeyToAccount(self.DEFAULT_TEST_ACCOUNT_KEY)
        print(f'Using EVM account {self.evmAccount.address}')

        self.cross_space_transfer(self.evmAccount.address, 1000 * 10 ** 18)

        self.eth_call_test()
        self.block_tx_root_test()

    # eth_call should support both "data" and "input" fields
    def eth_call_test(self):
        addr = self.deploy_evm_space_erc20()
        print(f'ERC20 contract address: {addr}')

        erc20 = self.load_contract(addr, "erc20")
        
        data = erc20.encodeABI(fn_name="balanceOf", args=[self.evmAccount.address])

        res1 = self.nodes[0].ethrpc.eth_call({
            "from": self.evmAccount.address,
            "to": addr,
            "data": data,
        })

        res2 = self.nodes[0].ethrpc.eth_call({
            "from": self.evmAccount.address,
            "to": addr,
            "input": data,
        })

        assert_equal(res1, res2)

    def block_tx_root_test(self):
        empty_hash = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        block_number = self.w3.eth.block_number
        self.rpc.generate_block(1)
        block = self.w3.eth.get_block(block_number + 1)
        assert_equal(toHex(block["receiptsRoot"]), empty_hash)
        assert_equal(toHex(block["transactionsRoot"]), empty_hash)




if __name__ == "__main__":
    EspaceRpcTest().main()