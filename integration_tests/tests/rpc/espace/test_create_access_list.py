import pytest

from integration_tests.test_framework.util import load_contract_metadata


@pytest.fixture(scope="module")
def storage_contract(ew3):
    contract_meta = load_contract_metadata("Storage")
    contract_factory = ew3.eth.contract(
        abi=contract_meta["abi"], bytecode=contract_meta["bytecode"]
    )
    tx_hash = contract_factory.constructor().transact()
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1

    return ew3.eth.contract(
        address=receipt["contractAddress"], abi=contract_meta["abi"]
    )


@pytest.fixture(scope="module")
def call_tools_contract(ew3):
    contract_meta = load_contract_metadata("CallTools")
    contract_factory = ew3.eth.contract(
        abi=contract_meta["abi"], bytecode=contract_meta["bytecode"]
    )
    tx_hash = contract_factory.constructor().transact()
    receipt = ew3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt["status"] == 1

    return ew3.eth.contract(
        address=receipt["contractAddress"], abi=contract_meta["abi"]
    )


def create_access_list(ew3, sender, to, data):
    result = dict(
        ew3.manager.request_blocking(
            "eth_createAccessList",
            [{"from": sender, "to": to, "data": data}, "latest"],
        )
    )
    # The node collects touched addresses in a HashMap, so the entry order of
    # the returned list is not deterministic. Sort before comparing.
    result["accessList"] = sorted(
        result["accessList"], key=lambda item: item["address"]
    )
    return result


def test_create_access_list_for_eoa_transfer(ew3, evm_accounts):
    receiver = ew3.eth.account.create()
    result = ew3.manager.request_blocking(
        "eth_createAccessList",
        [
            {
                "from": evm_accounts[0].address,
                "to": receiver.address,
                "value": "0x1",
            },
            "latest",
        ],
    )

    assert result == {"accessList": [], "gasUsed": "0x5208"}


def test_create_access_list_for_storage_access(
    ew3, evm_accounts, storage_contract
):
    storage_slot = 7
    data = storage_contract.encode_abi(
        abi_element_identifier="change", args=[storage_slot]
    )
    result = ew3.manager.request_blocking(
        "eth_createAccessList",
        [
            {
                "from": evm_accounts[0].address,
                "to": storage_contract.address,
                "data": data,
            },
            "latest",
        ],
    )

    assert "error" not in result
    assert int(result["gasUsed"], 16) > 21_000
    assert result["accessList"] == [
        {
            "address": storage_contract.address.lower(),
            "storageKeys": [f"0x{storage_slot:064x}"],
        }
    ]


def test_create_access_list_with_undefined_opcode(ew3, evm_accounts):
    # `0x0c` is not a defined instruction. The tracer is handed every opcode
    # before the interpreter gets a chance to reject it, so an undefined byte
    # must leave the node standing and simply report the failed execution.
    result = ew3.manager.request_blocking(
        "eth_createAccessList",
        [{"from": evm_accounts[0].address, "data": "0x0c"}, "latest"],
    )

    assert result["accessList"] == []
    assert "Bad instruction c" in result["error"]

    # The node is still serving requests.
    assert ew3.eth.block_number >= 0


def test_create_access_list_for_call_to_eoa(
    ew3, evm_accounts, call_tools_contract
):
    # A CALL records the callee address even when the callee has no code and
    # touches no storage. Because nothing else in this trace can contribute an
    # entry, the result pins down the CALL branch of the tracer on its own: the
    # address must come from the second stack item (the callee), not from the
    # top one (the gas argument).
    callee = ew3.eth.account.create().address
    data = call_tools_contract.encode_abi(
        abi_element_identifier="callAnother", args=[callee, b"", 0]
    )

    result = create_access_list(
        ew3, evm_accounts[0].address, call_tools_contract.address, data
    )

    assert "error" not in result
    assert result["accessList"] == [
        {"address": callee.lower(), "storageKeys": []}
    ]


def test_create_access_list_for_call_to_contract(
    ew3, evm_accounts, call_tools_contract, storage_contract
):
    # The callee is reached through a CALL and writes a storage slot, so it must
    # appear exactly once, carrying the slot it touched. The caller is the
    # transaction's `to` and stays excluded.
    storage_slot = 11
    inner_data = storage_contract.encode_abi(
        abi_element_identifier="change", args=[storage_slot]
    )
    data = call_tools_contract.encode_abi(
        abi_element_identifier="callAnother",
        args=[storage_contract.address, ew3.to_bytes(hexstr=inner_data), 0],
    )

    result = create_access_list(
        ew3, evm_accounts[0].address, call_tools_contract.address, data
    )

    assert "error" not in result
    assert int(result["gasUsed"], 16) > 21_000
    assert result["accessList"] == [
        {
            "address": storage_contract.address.lower(),
            "storageKeys": [f"0x{storage_slot:064x}"],
        }
    ]
