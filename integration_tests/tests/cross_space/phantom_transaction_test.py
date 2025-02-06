from typing import Type
import pytest
from integration_tests.conflux.rpc import RpcClient
from integration_tests.tests.cross_space.util import encode_bytes20, encode_u256
from integration_tests.test_framework.blocktools import encode_hex_0x
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.conflux.utils import sha3 as keccak


TEST_EVENT_TOPIC = encode_hex_0x(keccak(b"TestEvent(uint256)"))

# TODO: add test case
def test_a(gen_txs):
    pass


@pytest.fixture(scope="module")
def framework_class() -> Type[ConfluxTestFramework]:
    class DefaultFramework(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["min_native_base_price"] = 10000
            self.conf_parameters["next_hardfork_transition_height"] = 1
            self.conf_parameters["next_hardfork_transition_number"] = 1

        def setup_network(self):
            print("set network archive")
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])
            self.rpc = RpcClient(self.nodes[0])

    return DefaultFramework



@pytest.fixture(scope="module")
def core_contract(network: ConfluxTestFramework):
    return network.deploy_contract("CrossSpaceEventTestConfluxSide")


@pytest.fixture(scope="module")
def evm_contract(network: ConfluxTestFramework):
    return network.deploy_evm_contract("CrossSpaceEventTestEVMSide")


#                              ---
#           .-----------------| D |....
#           V                  ---    |
#          ---      ---      ---      ---
# ... <-- | A | <- | B | <- | C | <- | E | <- ...
#          ---      ---      ---      ---
#
#                 A --- B --- C --- D --- E
# block number    0  |  1  |  2  |  3  |  4  |
# epoch number    0  |  1  |  2  |     3     |
@pytest.fixture(scope="module")
def gen_txs(
    core_contract, evm_contract, evm_accounts, core_accounts, cw3, ew3, network
):
    print("gen txs start")

    evm_account = evm_accounts[0]
    core_account = core_accounts[0]
    client = network.client

    cfx_next_nonce = cw3.cfx.get_next_nonce(core_account.address)
    cfx_tx_hashes = []

    evm_next_nonce = ew3.eth.get_transaction_count(evm_account.address)
    evm_tx_hashes = []

    def emitConflux(n):
        nonlocal cfx_next_nonce, cfx_tx_hashes
        data_hex = encode_hex_0x(keccak(b"emitConflux(uint256)"))[:10] + encode_u256(n)
        tx = client.new_contract_tx(
            receiver=core_contract.address.hex_address,
            data_hex=data_hex,
            nonce=cfx_next_nonce,
            priv_key=core_account.key,
        )
        cfx_next_nonce += 1
        cfx_tx_hashes.append(tx.hash_hex())
        return tx

    def emitComplex(n):
        nonlocal cfx_next_nonce, cfx_tx_hashes
        data_hex = (
            encode_hex_0x(keccak(b"emitComplex(uint256,bytes20)"))[:10]
            + encode_u256(n)
            + encode_bytes20(evm_contract.address.replace("0x", ""))
        )
        tx = client.new_contract_tx(
            receiver=core_contract.address.hex_address,
            data_hex=data_hex,
            nonce=cfx_next_nonce,
            priv_key=core_account.key,
        )
        cfx_next_nonce += 1
        cfx_tx_hashes.append(tx.hash_hex())
        return tx

    def emitEVM(n):
        nonlocal evm_next_nonce, evm_tx_hashes
        data_hex = encode_hex_0x(keccak(b"emitEVM(uint256)"))[:10] + encode_u256(n)
        tx, hash = construct_evm_tx(
            evm_account,
            receiver=evm_account.address,
            data_hex=data_hex,
            nonce=evm_next_nonce,
        )
        evm_next_nonce += 1
        evm_tx_hashes.append(hash)
        return tx

    print("ready to gen blocks")
    # generate ledger
    block_0 = client.block_by_epoch("latest_mined")["hash"]

    print("get block 0")

    block_a = client.generate_custom_block(
        parent_hash=block_0,
        referee=[],
        txs=[
            emitConflux(11),
            emitEVM(12),
            emitComplex(13),
        ],
    )

    print("gen block a")

    block_b = client.generate_custom_block(
        parent_hash=block_a,
        referee=[],
        txs=[
            emitConflux(14),
            emitEVM(15),
            emitComplex(16),
        ],
    )

    print("gen block b")

    block_c = client.generate_custom_block(parent_hash=block_b, referee=[], txs=[])

    block_d = client.generate_custom_block(
        parent_hash=block_a,
        referee=[],
        txs=[
            emitConflux(21),
            emitEVM(22),
            emitComplex(23),
        ],
    )

    print("gen block d")

    block_e = client.generate_custom_block(
        parent_hash=block_c,
        referee=[block_d],
        txs=[
            emitConflux(24),
            emitEVM(25),
            emitComplex(26),
        ],
    )

    print("gen block e")

    [epoch_a, block_number_a] = [
        client.block_by_hash(block_a)[key] for key in ["epochNumber", "blockNumber"]
    ]
    [epoch_b, block_number_b] = [
        client.block_by_hash(block_b)[key] for key in ["epochNumber", "blockNumber"]
    ]
    [epoch_d, block_number_d] = [
        client.block_by_hash(block_d)[key] for key in ["epochNumber", "blockNumber"]
    ]
    [epoch_e, block_number_e] = [
        client.block_by_hash(block_e)[key] for key in ["epochNumber", "blockNumber"]
    ]

    print("gen block with txs complete")
    # make sure transactions have been executed
    parent_hash = block_e

    for _ in range(5):
        block = client.generate_custom_block(
            parent_hash=parent_hash, referee=[], txs=[]
        )
        parent_hash = block

    print("gen block complete, wait transactions")

    for h in cfx_tx_hashes:
        receipt = cw3.cfx.wait_for_transaction_receipt(h)
        assert receipt["outcomeStatus"] == 0

    for h in evm_tx_hashes:
        receipt = ew3.eth.wait_for_transaction_receipt(h)
        assert receipt["status"] == "0x1"

    return {
        "epoch_a": epoch_a,
        "epoch_b": epoch_b,
        "epoch_d": epoch_d,
        "epoch_e": epoch_e,
        "block_number_a": block_number_a,
        "block_number_b": block_number_b,
        "block_number_d": block_number_d,
        "block_number_e": block_number_e,
    }


def construct_evm_tx(evm_account, receiver, data_hex, nonce):
    signed = evm_account.sign_transaction(
        {
            "to": receiver,
            "value": 0,
            "gasPrice": 1,
            "gas": 150000,
            "nonce": nonce,
            "chainId": 11,
            "data": data_hex,
        }
    )

    tx = [
        nonce,
        1,
        150000,
        bytes.fromhex(receiver.replace("0x", "")),
        0,
        bytes.fromhex(data_hex.replace("0x", "")),
        signed["v"],
        signed["r"],
        signed["s"],
    ]
    return tx, signed["hash"]
