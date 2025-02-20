import re

from web3 import Web3

from conflux.address import hex_to_b32_address
from conflux.rpc import RpcClient
from conflux.utils import *
from test_framework.test_framework import ConfluxTestFramework
from test_framework.util import *
from test_framework.mininode import *
from os.path import dirname, realpath, join

CFX = 10 ** 18
BYTE_COLLATERAL = int(CFX / 1024)
ENTRY_COLLATERAL = BYTE_COLLATERAL * 64
SPONSOR_INTERNAL_CONTRACT = "0888000000000000000000000000000000000001"
ZERO_ADDR = Web3.to_checksum_address("0" * 40)


class EstimationTest(ConfluxTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test(self):
        client = RpcClient(self.nodes[0])
        rpc = self.nodes[0].rpc
        w3 = web3.Web3()
        start_p2p_connection(self.nodes)
        priv = default_config["GENESIS_PRI_KEY"]
        senator = encode_hex(priv_to_addr(priv))
        from_senator = {"from": hex_to_b32_address(senator)}

        user_pri = "3" * 64
        user = encode_hex(priv_to_addr(user_pri))
        from_user = {"from": hex_to_b32_address(user)}

        def send_tx(tx):
            client.send_tx(tx, True)
            self.wait_for_tx([tx], True)

        def estimate(**data):
            return rpc.cfx_estimateGasAndCollateral(data)

        def estimate_error(**data):
            try:
                rpc.cfx_estimateGasAndCollateral(data)
            except ReceivedErrorResponseError as e:
                error = e.response
                return error
            except Exception as e:
                raise AssertionError("Unexpected exception raised: " +
                                     type(e).__name__)
            raise AssertionError("Expected raise exception")

        def clear_user_balance():
            if client.get_balance(user) - 21000 > 0:
                send_tx(client.new_contract_tx(senator, value=client.get_balance(user) - 21000, priv_key=user_pri))

        (abi, bytecode) = storage_contract()
        tx = client.new_contract_tx(None, bytecode, gas=500000, storage_limit=1024)
        send_tx(tx)
        receipt = client.get_transaction_receipt(tx.hash_hex())
        contract = w3.eth.contract(abi=abi, address=Web3.to_checksum_address(receipt["contractCreated"]))
        contract_address = contract.address
        contract_base32_address = hex_to_b32_address(contract.address)

        ## Stage 1: no sponsor
        # Normal transaction
        res = estimate(to=contract_base32_address)
        send_tx(
            client.new_contract_tx(contract_address, gas=res["gasLimit"], storage_limit=res["storageCollateralized"]))
        # If there is no sender, estimate will not check balance
        estimate(to=hex_to_b32_address(user), value=hex(1_000_000_000 * CFX))

        # Deep Recursive and Set Entries
        data = contract.encode_abi("recursive", [100])
        res = estimate(to=contract_base32_address, data=data)
        send_tx(client.new_contract_tx(contract_address, gas=res["gasLimit"], data_hex=data,
                                       storage_limit=res["storageCollateralized"]))

        # Repeatedly Set the Same Entry
        data = contract.encode_abi("recursive", [0])
        # For a random sender, it needs to pay for the collateral for resetting entries.
        res = estimate(to=contract_base32_address, data=data)
        assert_equal(int(res["storageCollateralized"], 0), 128)
        # When estimating with entry owner, the estimation knows that no need to pay for collateral again.
        res = estimate(to=contract_base32_address, data=data, **from_senator)
        assert_equal(int(res["storageCollateralized"], 0), 0)

        # Same task as above, but with a poor user.
        print(client.get_balance(user))
        error = estimate_error(to=contract_base32_address, data=data, gasPrice="0x1", **from_user)
        (_, _, _, storage_limit) = parse_not_enough_cash(error.message)
        assert_equal(storage_limit, 128 * BYTE_COLLATERAL)
        send_tx(client.new_contract_tx(user, value=128 * BYTE_COLLATERAL))
        # Give the user some collateral, then the estimation can pass, even it has no more balance for gas
        estimate(to=contract_base32_address, data=data, **from_user)
        # If gas price is not none, the execution fails.
        error = estimate_error(to=contract_base32_address, data=data, gasPrice="0x1", **from_user)
        parse_not_enough_cash(error.message)
        send_tx(client.new_contract_tx(user, value=40000))
        # If the user gives insufficient gas, the execution fails.
        error = estimate_error(to=contract_base32_address, data=data, gasPrice="0x1", gas=hex(30000), **from_user)
        parse_out_of_gas(error.message)
        # Finally, an acceptable estimation
        res = estimate(to=contract_base32_address, data=data, gasPrice="0x1", **from_user)
        send_tx(client.new_contract_tx(contract_address, gas=res["gasLimit"], data_hex=data,
                                       storage_limit=res["storageCollateralized"], priv_key=user_pri))

        sponsor_contract = w3.eth.contract(abi=sponsor_abi())

        # # Sponsor gas for this contract.
        send_tx(client.new_contract_tx(receiver=SPONSOR_INTERNAL_CONTRACT,
                                       data_hex=sponsor_contract.encode_abi("setSponsorForGas",
                                                                           [contract_address, 30_000_000]),
                                       value=30_000_000_000))
        send_tx(client.new_contract_tx(receiver=SPONSOR_INTERNAL_CONTRACT,
                                       data_hex=sponsor_contract.encode_abi("addPrivilegeByAdmin",
                                                                           [contract_address, [ZERO_ADDR]]),
                                       storage_limit=64))

        # Again, the user can send transaction, even without enough balance
        res = estimate(to=contract_base32_address, data=data, gasPrice=hex(10), **from_user)
        gas_limit = int(res["gasLimit"], 0)
        send_tx(client.new_contract_tx(contract_address, gas=res["gasLimit"], data_hex=data,
                                       storage_limit=res["storageCollateralized"], priv_key=user_pri))
        # But if the gas price is too high, the transaction can not be sponsored
        error = estimate_error(to=contract_base32_address, data=data, gasPrice=hex(10000), **from_user)
        parse_not_enough_cash(error.message)
        # Now lets run out of sponsor gas
        self.log.info("Running out of sponsor gas, it may take 1 minute")
        while True:
            balance = client.get_sponsor_balance_for_gas(contract_address)
            if balance < 300_000:
                break
            max_cost = min(balance, 30_000_000)
            gas_price = max_cost // gas_limit
            send_tx(client.new_contract_tx(contract_address, gas=hex(gas_limit), gas_price=gas_price, data_hex=data,
                                           storage_limit=0, priv_key=user_pri))
        self.log.info("Done")
        # Now the transaction can not be sponsored since it does not have enough balance.
        error = estimate_error(to=contract_base32_address, data=data, gasPrice=hex(10), **from_user)
        parse_not_enough_cash(error.message)
        send_tx(client.new_contract_tx(user, value=400_000))
        # If the sender have enough balance, the estimation success
        estimate(to=contract_base32_address, data=data, gasPrice=hex(10), **from_user)

        # Sponsor gas for this contract.
        send_tx(client.new_contract_tx(receiver=SPONSOR_INTERNAL_CONTRACT,
                                       data_hex=sponsor_contract.encode_abi("setSponsorForCollateral",
                                                                           [contract_address]),
                                       value=5 * ENTRY_COLLATERAL))

        data = contract.encode_abi("inc_prefix", [4])
        res = estimate(to=contract_base32_address, data=data, **from_user)
        send_tx(client.new_contract_tx(contract_address, gas=res["gasLimit"], data_hex=data,
                                       storage_limit=res["storageCollateralized"], priv_key=user_pri))

        # The sponsor have enough balance for collateral, only pay for additional.
        data = contract.encode_abi("inc_prefix", [5])
        res = estimate(to=contract_base32_address, data=data)
        assert_equal(int(res["storageCollateralized"], 0), 64)

        # The sponsor don't have enough balance for collateral
        data = contract.encode_abi("inc_prefix", [6])
        res = estimate(to=contract_base32_address, data=data)
        assert_equal(int(res["storageCollateralized"], 0), 6 * 64)

        # The user overcome
        send_tx(client.new_contract_tx(user, value=20 * ENTRY_COLLATERAL + 1_000_000))
        data = contract.encode_abi("inc_prefix", [7])
        res = estimate(to=contract_base32_address, data=data, **from_user)
        assert_equal(int(res["storageCollateralized"], 0), 7 * 64)
        send_tx(client.new_contract_tx(contract_address, gas=res["gasLimit"], data_hex=data,
                                       storage_limit=res["storageCollateralized"], priv_key=user_pri))

        data = contract.encode_abi("inc_prefix", [8])
        res = estimate(to=contract_base32_address, data=data, **from_user)
        assert_equal(int(res["storageCollateralized"], 0), 6 * 64)
        send_tx(client.new_contract_tx(contract_address, gas=res["gasLimit"], data_hex=data,
                                       storage_limit=res["storageCollateralized"], priv_key=user_pri))

        data = contract.encode_abi("inc_prefix", [3])
        res = estimate(to=contract_base32_address, data=data, **from_user)
        assert_equal(int(res["storageCollateralized"], 0), 3 * 64)

        estimate(data=bytecode, **from_senator)
        error = estimate_error(data=bytecode, nonce=hex(0), **from_senator)
        parse_conflict_address(error.message)


def parse_not_enough_cash(msg):
    pattern = "NotEnoughCash { required: ([0-9]+), got: ([0-9]+), actual_gas_cost: ([0-9]+), max_storage_limit_cost: ([0-9]+) }"
    m = re.search(pattern, msg)
    if m is None:
        raise AssertionError(f"Can not parse NotEnoughCash error: {msg}")
    return (int(s) for s in m.groups())


def parse_conflict_address(msg):
    if re.search("VmError\\(ConflictAddress\\(0x8[0-9a-z]{19,}\\)\\)", msg) is None:
        raise AssertionError(f"Not ConflictAddress error: {msg}")


def parse_out_of_gas(msg):
    if re.search("VmError\\(OutOfGas\\)", msg) is None:
        raise AssertionError(f"Not OutOfGas error: {msg}")


def storage_contract():
    bytecode_path = join(dirname(realpath(__file__)),
                         *"contracts/set_storage_for_est.bytecode".split("/"))
    bytecode = open(bytecode_path, "r").read()

    abi_path = join(dirname(realpath(__file__)),
                    *"contracts/set_storage_for_est.json".split("/"))
    abi = json.loads(open(abi_path, "r").read())

    return abi, "0x" + bytecode


def sponsor_abi():
    abi_path = join(dirname(realpath(__file__)),
                    *"../internal_contract/metadata/SponsorWhitelistControl.json".split("/"))
    abi = json.loads(open(abi_path, "r").read())["abi"]

    return abi


if __name__ == "__main__":
    EstimationTest().main()
