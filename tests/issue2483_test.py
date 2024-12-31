#!/usr/bin/env python3
from conflux.rpc import RpcClient, convert_b32_address_field_to_hex
from conflux.utils import priv_to_addr, parse_as_int
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *

CONTRACT_BYTECODE = "contracts/simple_storage.dat"
CONTRACT_ABI = "contracts/simple_storage.abi"


class Issue2483(ConfluxTestFramework):
    def __init__(self):
        super(Issue2483, self).__init__()

    def set_test_params(self):
        self.num_nodes = 1
        self.gasPrice = 1
        self.conf_parameters["executive_trace"] = "true"

    def setup_network(self):
        self.setup_nodes()

    def run_test(self):
        self.rpc = RpcClient(self.nodes[0])
        priv_key = default_config["GENESIS_PRI_KEY"]
        sender = eth_utils.encode_hex(priv_to_addr(priv_key))

        # deploy storage test contract
        bytecode_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_BYTECODE)
        bytecode = open(bytecode_file).read()
        abi_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), CONTRACT_ABI)
        abi = json.loads(open(abi_file).read())
        tx = self.rpc.new_contract_tx(receiver="", data_hex=bytecode, sender=sender, priv_key=priv_key,
                                      storage_limit=20000)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        contract_address = receipt["contractCreated"]

        contract = web3.Web3().eth.contract(abi=abi)
        call_data = contract.encode_abi("setFresh")

        tx = self.rpc.new_contract_tx(receiver=contract_address, data_hex=call_data)
        assert_equal(self.rpc.send_tx(tx, True), tx.hash_hex())

        # The transaction should be reverted by exceeding storage limit
        receipt = self.rpc.get_transaction_receipt(tx.hash_hex())
        assert_equal(receipt["outcomeStatus"], "0x1")
        assert_equal(receipt["txExecErrorMsg"], "VmError(ExceedStorageLimit)")

        traces = self.rpc.get_transaction_trace(tx.hash_hex())

        def simplify_trace(trace):
            answer = dict()
            answer['action'] = trace['action']
            answer['type'] = trace['type']
            answer['valid'] = trace['valid']
            action = answer['action']
            convert_b32_address_field_to_hex(action, "from")
            convert_b32_address_field_to_hex(action, "to")

            return answer

        traces = [simplify_trace(trace) for trace in traces]
        zero = '0x0000000000000000000000000000000000000000'
        answer = [{
            'action': {
                'from': sender,
                'fromPocket': 'balance',
                'fromSpace': 'native',
                'to': zero,
                'toPocket': 'gas_payment',
                'toSpace': 'none',
                'value': '0x2dc6c0'
            },
            'type': 'internal_transfer_action',
            'valid': True
        }, {
            'action': {
                'callType': 'call',
                'from': sender,
                'gas': '0x2d73a8',
                'input': '0x28d05e21',
                'space': 'native',
                'to': contract_address,
                'value': '0x0'
            },
            'type': 'call',
            'valid': False
        }, {
            'action': {
                'gasLeft': '0x2d5f8d',
                'outcome': 'success',
                'returnData': '0x'
            },
            'type': 'call_result',
            'valid': False
        }, {
            'action': {
                'from': sender,
                'fromPocket': 'balance',
                'fromSpace': 'native',
                'to': sender,
                'toPocket': 'storage_collateral',
                'toSpace': 'native',
                'value': '0xde0b6b3a764000'
            },
            'type': 'internal_transfer_action',
            'valid': False
        }, {
            'action': {
                'from': zero,
                'fromPocket': 'gas_payment',
                'fromSpace': 'none',
                'to': sender,
                'toPocket': 'balance',
                'toSpace': 'native',
                'value': '0x0'
            },
            'type': 'internal_transfer_action',
            'valid': True
        }]

        assert_equal(traces, answer)


if __name__ == "__main__":
    Issue2483().main()
