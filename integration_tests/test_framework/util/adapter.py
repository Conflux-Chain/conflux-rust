from typing import Optional

from web3 import Web3
from eth_account.signers.local import LocalAccount
from ethereum_test_types import EOA
from ethereum_test_tools import (
    Address,
    Bytecode,
    Initcode,
)
from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
)


class AllocMock:
    def __init__(self, ew3: Web3, genesis_account: LocalAccount):
        self.ew3 = ew3
        self.genesis_account = genesis_account
    
    def fund_eoa(self, amount: Optional[int] = None, delegation: Optional[Address] = None) -> EOA:
        if amount is None:
            amount = self.ew3.to_wei(1, "ether")
        new_account = self.ew3.eth.account.create()
        tx_hash = self.ew3.eth.send_transaction(
            {
                "from": self.genesis_account.address,
                "to": new_account.address,
                "value": amount,
            }
        )
        self.ew3.eth.wait_for_transaction_receipt(tx_hash)
        if delegation is not None:
            tx_hash = send_eip7702_transaction(
                self.ew3,
                self.genesis_account,
                {
                    "authorizationList": [
                        sign_authorization(
                            contract_address=str(delegation),
                            chain_id=self.ew3.eth.chain_id,
                            nonce=0,
                            private_key=new_account.key.to_0x_hex(),
                        )
                    ],
                    "to": "0x0000000000000000000000000000000000000000",
                }
            )
            self.ew3.eth.wait_for_transaction_receipt(tx_hash)
        return EOA(key=new_account.key)
    
    def deploy_contract(self, code: Bytecode) -> Address:
        # 创建初始化代码并部署合约
        initcode = Initcode(deploy_code=code)
        tx_hash = self.ew3.eth.send_transaction(
            {
                "from": self.genesis_account.address,
                "data": bytes(initcode),
            }
        )
        receipt = self.ew3.eth.wait_for_transaction_receipt(tx_hash)
        return Address(receipt["contractAddress"])
    