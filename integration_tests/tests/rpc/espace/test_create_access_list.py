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
