import pytest

from web3 import Web3
from web3.middleware.signing import SignAndSendRawMiddlewareBuilder
from ethereum_test_tools import (
    Account,
    Address,
    Environment,
    Transaction,
)

from integration_tests.test_framework.util.eip7702.eip7702 import (
    sign_authorization,
    send_eip7702_transaction,
    Authorization,
)
from integration_tests.test_framework.test_framework import ConfluxTestFramework
from integration_tests.test_framework.util.adapter import AllocMock

MIN_NATIVE_BASE_PRICE = 10000
# set to 1 because this is the chain id of ethereum execution spec tests
EVM_CHAIN_ID = 1

@pytest.fixture(scope="module")
def framework_class():
    class EIP7702TestEnv(ConfluxTestFramework):
        def set_test_params(self):
            self.num_nodes = 1
            self.conf_parameters["evm_chain_id"] = str(EVM_CHAIN_ID)
            self.conf_parameters["eoa_code_transition_height"] = 1
            self.conf_parameters["evm_transaction_block_ratio"] = str(1)

        def setup_network(self):
            self.add_nodes(self.num_nodes)
            self.start_node(0, ["--archive"])

    return EIP7702TestEnv

@pytest.fixture(scope="module")
def state_test(ew3: Web3, network: ConfluxTestFramework):
    def conflux_state_test(
        env: Environment,
        pre: AllocMock,
        tx: Transaction,
        post: dict[Address, Account],
        t8n_dump_dir=None,  # Optional parameter
    ):
        # assert tx.authorization_list is not None
        
        if tx.authorization_list is not None:
            # Send transaction
            tx_hash = send_eip7702_transaction(
                ew3, 
                ew3.eth.account.from_key(tx.sender.key),  # type: ignore
                {
                    "nonce": tx.nonce,
                    "value": tx.value,
                    "to": tx.to.hex() if tx.to is not None else None,
                    "gas": tx.gas_limit,
                    "data": tx.data.hex() if tx.data is not None else None,
                    "authorizationList": [
                        sign_authorization(
                            str(auth.address),
                            auth.chain_id,
                            int(auth.nonce),  # Convert to int to fix type error
                            auth.signer.key.hex(),  # type: ignore
                        # if auth.signer.key is not None else 
                        # Authorization(
                        #     contract_address=str(auth.address),
                        #     chain_id=auth.chain_id,
                        #     nonce=int(auth.nonce),
                        #     r=hex(auth.r),
                        #     s=hex(auth.s),
                        #     v=auth.v,
                        #     yParity=0
                        ) for auth in tx.authorization_list 
                    ] if tx.authorization_list is not None else None
                }
            )
        else:
            tx_to_send = {
                "from": tx.sender,
                "nonce": tx.nonce,
                "value": tx.value,
                "to": tx.to,
                "gas": tx.gas_limit,
                "data": tx.data,
            }
            ew3.middleware_onion.add(SignAndSendRawMiddlewareBuilder.build(tx.sender.key))
            tx_hash = ew3.eth.send_transaction(tx_to_send)

        # output tx_hash, sender nonce, sender balance, tx data
        print(f"tx_hash: {tx_hash.hex()}")
        print(f"sender nonce: {ew3.eth.get_transaction_count(tx.sender)}")
        print(f"tx data: {ew3.eth.get_transaction(tx_hash)}")
        print(f"pending txs: {ew3.manager.request_blocking('eth_getAccountPendingTransactions', [tx.sender.hex()])}")
        network.client.generate_blocks(5, num_txs=1)
        print("--------generate blocks-----------------")
        print(f"tx_hash: {tx_hash.hex()}")
        print(f"sender nonce: {ew3.eth.get_transaction_count(tx.sender)}")
        print(f"tx data: {ew3.eth.get_transaction(tx_hash)}")
        print(f"pending txs: {ew3.manager.request_blocking('eth_getAccountPendingTransactions', [tx.sender.hex()])}")
        receipt = ew3.eth.wait_for_transaction_receipt(tx_hash, timeout=10, poll_latency=0.2)
        
        # Check post-conditions
        # Collect all state differences instead of breaking on first failure
        differences = []
        
        for address, expected_account in post.items():
            # Convert Address to string for web3 compatibility
            address_str = ew3.to_checksum_address(address)

            # Handle non-existent accounts
            if expected_account is None:
                try:
                    actual_nonce = ew3.eth.get_transaction_count(address_str)
                    if actual_nonce != 0:
                        differences.append(f"Account {address} nonce should be 0, actual: {actual_nonce}")
                except Exception as e:
                    differences.append(f"Error checking nonce for account {address}: {str(e)}")
                
                try:
                    actual_code = ew3.eth.get_code(address_str)
                    if actual_code != b'':
                        differences.append(f"Account {address} code should be empty, actual: {actual_code.hex()}")
                except Exception as e:
                    differences.append(f"Error checking code for account {address}: {str(e)}")
                
                try:
                    actual_balance = ew3.eth.get_balance(address_str)
                    if actual_balance != 0:
                        differences.append(f"Account {address} balance should be 0, actual: {actual_balance}")
                except Exception as e:
                    differences.append(f"Error checking balance for account {address}: {str(e)}")
                
                continue
            
            # Check nonce
            if expected_account.nonce != 0:
                try:
                    actual_nonce = ew3.eth.get_transaction_count(address_str)
                    if actual_nonce != expected_account.nonce:
                        differences.append(f"Account {address} nonce mismatch: expected={expected_account.nonce}, actual={actual_nonce}")
                except Exception as e:
                    differences.append(f"Error checking nonce for account {address}: {str(e)}")
            
            # Check code
            if expected_account.code != b'':
                try:
                    actual_code = ew3.eth.get_code(address_str)
                    if actual_code != expected_account.code:
                        differences.append(f"Account {address} code mismatch: expected length={len(expected_account.code)}, actual length={len(actual_code)}")
                        if len(actual_code) < 100 and len(expected_account.code) < 100:
                            differences.append(f"  Expected code: {expected_account.code.hex()}")
                            differences.append(f"  Actual code: {actual_code.hex()}")
                except Exception as e:
                    differences.append(f"Error checking code for account {address}: {str(e)}")
            
            # Check storage
            if hasattr(expected_account, 'storage') and expected_account.storage is not None:
                for key, expected_value in expected_account.storage.items():
                    try:
                        actual_value = int(ew3.eth.get_storage_at(address_str, key).hex(), 16)
                        if actual_value != expected_value:
                            differences.append(f"Account {address} storage slot {key} mismatch: expected={expected_value}, actual={actual_value}")
                    except Exception as e:
                        differences.append(f"Error checking storage slot {key} for account {address}: {str(e)}")
        
        # If differences found, display in table format and raise exception
        if differences:
            error_message = "\nState validation failed, found the following differences:\n" + "\n".join(differences)
            
            # Add comprehensive state differences table
            error_message += "\n\nState Differences Table:\n"
            error_message += "+----------------+----------+------------------+------------------+\n"
            error_message += "| Address        | Type     | Expected         | Actual           |\n"
            error_message += "+----------------+----------+------------------+------------------+\n"
            
            for address, expected_account in post.items():
                address_str = ew3.to_checksum_address(address)
                addr_short = f"{str(address_str)[:6]}...{str(address_str)[-4:]}"
                
                if expected_account is None:
                    # Non-existent account
                    error_message += f"| {addr_short:<14} | existence | Non-existent      | "
                    try:
                        actual_nonce = ew3.eth.get_transaction_count(address_str)
                        actual_code = ew3.eth.get_code(address_str)
                        actual_balance = ew3.eth.get_balance(address_str)
                        if actual_nonce == 0 and actual_code == b'' and actual_balance == 0:
                            error_message += "Default state     |\n"
                        else:
                            error_message += "Exists            |\n"
                    except Exception as e:
                        error_message += f"Check failed      |\n"
                else:
                    # Check nonce
                    if expected_account.nonce != 0:
                        error_message += f"| {addr_short:<14} | nonce    | {expected_account.nonce:<16} | "
                        try:
                            actual_nonce = ew3.eth.get_transaction_count(address_str)
                            error_message += f"{actual_nonce:<16} |\n"
                        except Exception as e:
                            error_message += f"Check failed      |\n"
                    
                    # Check code
                    if expected_account.code != b'':
                        error_message += f"| {addr_short:<14} | code     | {len(expected_account.code)} bytes         | "
                        try:
                            actual_code = ew3.eth.get_code(address_str)
                            error_message += f"{len(actual_code)} bytes         |\n"
                        except Exception as e:
                            error_message += f"Check failed      |\n"
                    
                    # Check balance if specified
                    if hasattr(expected_account, 'balance') and expected_account.balance is not None:
                        error_message += f"| {addr_short:<14} | balance  | {expected_account.balance:<16} | "
                        try:
                            actual_balance = ew3.eth.get_balance(address_str)
                            error_message += f"{actual_balance:<16} |\n"
                        except Exception as e:
                            error_message += f"Check failed      |\n"
                    
                    # Check storage
                    if hasattr(expected_account, 'storage') and expected_account.storage is not None:
                        for key, expected_value in expected_account.storage.items():
                            expected_hex = f"0x{expected_value:x}"
                            error_message += f"| {addr_short:<14} | slot {key:<4} | {expected_hex:<16} | "
                            try:
                                actual_value = int(ew3.eth.get_storage_at(address_str, key).hex(), 16)
                                actual_hex = f"0x{actual_value:x}"
                                error_message += f"{actual_hex:<16} |\n"
                            except Exception as e:
                                error_message += f"Check failed      |\n"
            
            error_message += "+----------------+----------+------------------+------------------+"
            
            raise AssertionError(error_message)
    return conflux_state_test


@pytest.fixture(scope="module")
def pre(ew3, evm_accounts):
    return AllocMock(ew3, evm_accounts[-1])
