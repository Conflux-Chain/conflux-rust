use super::super::error::TestErrorKind;
use cfx_executor::{
    executive::{ChargeCollateral, TransactOptions, TransactSettings},
    machine::Machine,
    state::State,
};
use cfx_rpc_eth_types::{
    AccountOverride, AccountStateOverrideMode, StateOverride,
};
use cfx_statedb::StateDb;
use cfx_types::{
    h256_to_u256_be, u256_to_h256_be, AllChainID, Space, SpaceMap, H256, U256,
    U64,
};
use cfx_vm_types::Env;
use cfxcore::verification::{VerificationConfig, VerifyTxMode};
use cfxkey::{Address, Secret};
use primitives::{
    transaction::{
        Action, AuthorizationListItem, Eip1559Transaction, Eip155Transaction,
        Eip2930Transaction, Eip7702Transaction, EthereumTransaction,
        TransactionError,
    },
    SignedTransaction, Transaction,
};
use statetest_types::{
    AccountInfo, Env as StateTestEnv, SignedAuthorization, TransactionParts,
    TransactionType, TxPartIndices,
};
use std::{
    collections::{BTreeMap, HashMap},
    u64,
};

pub fn make_tx(
    tx_meta: &TransactionParts, tx_part_indices: &TxPartIndices, chain_id: u64,
    unprotected: bool,
) -> Option<SignedTransaction> {
    // basic fields
    let action = match tx_meta.to {
        Some(to) => Action::Call(to),
        None => Action::Create,
    };
    let nonce = tx_meta.nonce;
    let gas = tx_meta.gas_limit[tx_part_indices.gas];
    let value = tx_meta.value[tx_part_indices.value];
    let data = tx_meta.data[tx_part_indices.data].0.clone();
    let chain_id = chain_id as u32;

    let gas_price = tx_meta.gas_price.unwrap_or_default();

    // EIP-1559 fields
    let max_fee_per_gas = tx_meta.max_fee_per_gas.unwrap_or_default();
    let max_priority_fee_per_gas =
        tx_meta.max_priority_fee_per_gas.unwrap_or_default();

    let access_list = tx_meta
        .access_lists
        .get(tx_part_indices.data)
        .map(|item| item.clone())
        .unwrap_or(Some(vec![]))
        .unwrap_or_default();

    let tx = match tx_meta.tx_type(tx_part_indices.data) {
        Some(TransactionType::Legacy) => {
            let tx155_chain_id =
                if unprotected { None } else { Some(chain_id) };
            EthereumTransaction::Eip155(Eip155Transaction {
                nonce,
                gas_price,
                gas,
                action,
                value,
                data,
                chain_id: tx155_chain_id,
            })
        }
        Some(TransactionType::Eip2930) => {
            EthereumTransaction::Eip2930(Eip2930Transaction {
                nonce,
                gas_price,
                gas,
                action,
                value,
                data,
                chain_id,
                access_list,
            })
        }
        Some(TransactionType::Eip1559) => {
            EthereumTransaction::Eip1559(Eip1559Transaction {
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas,
                action,
                value,
                data,
                chain_id,
                access_list,
            })
        }
        Some(TransactionType::Eip4844) => {
            // conflux does not support EIP-4844
            return None;
        }
        Some(TransactionType::Eip7702) => {
            let authorization_list = tx_meta
                .authorization_list
                .clone()
                .expect("authorization list should be present")
                .into_iter()
                .map(|v| {
                    let auth = SignedAuthorization::from(v);
                    AuthorizationListItem {
                        address: auth.inner().address,
                        nonce: auth.inner().nonce,
                        chain_id: auth.inner().chain_id,
                        y_parity: auth.y_parity(),
                        r: auth.r(),
                        s: auth.s(),
                    }
                })
                .collect();

            EthereumTransaction::Eip7702(Eip7702Transaction {
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas,
                destination: tx_meta.to.unwrap_or_default(),
                value,
                data,
                chain_id,
                access_list,
                authorization_list,
            })
        }
        _ => {
            return None;
        }
    };

    let secret = Secret::from(tx_meta.secret_key);
    Some(Transaction::Ethereum(tx).sign(&secret))
}

pub fn make_transact_options(check_base_price: bool) -> TransactOptions<()> {
    let settings = TransactSettings {
        charge_collateral: ChargeCollateral::Normal,
        charge_gas: true,
        check_base_price,
        check_epoch_bound: false,
        forbid_eoa_with_code: true,
    };
    TransactOptions {
        observer: (),
        settings,
    }
}

pub fn make_state(pre_state: &HashMap<Address, AccountInfo>) -> State {
    // step1: setup the state according the pre state
    let mut state_override = StateOverride::new();
    for (address, info) in pre_state {
        let account_state: HashMap<H256, H256> = info
            .storage
            .iter()
            .map(|(k, v)| {
                (u256_to_h256_be(k.clone()), u256_to_h256_be(v.clone()))
            })
            .collect();
        state_override.insert(
            *address,
            AccountOverride {
                balance: Some(info.balance),
                nonce: Some(U64::from(info.nonce)),
                code: Some(info.code.0.clone()),
                state: AccountStateOverrideMode::State(account_state),
                move_precompile_to: None,
            },
        );
    }

    let statedb = StateDb::new_for_unit_test();

    let mut state =
        State::new_with_override(statedb, &state_override, Space::Ethereum)
            .expect("db error");
    state.commit_cache(false);
    state
}

pub fn make_block_env(
    machine: &Machine, env: &StateTestEnv, evm_chain_id: u64,
    transaction_hash: H256,
) -> Env {
    let config_chain_id: AllChainID =
        machine.params().chain_id.read().get_chain_id(0);
    let mut chain_id = BTreeMap::new();
    chain_id.insert(Space::Native, config_chain_id.in_native_space());
    chain_id.insert(Space::Ethereum, evm_chain_id as u32);

    let base_gas_price = env
        .current_base_fee
        .map(|v| SpaceMap::new(v, v))
        .unwrap_or_default();

    let blob_gas = env.current_excess_blob_gas.unwrap_or_default().as_u64();

    Env {
        chain_id,
        number: env.current_number.as_u64(),
        author: env.current_coinbase,
        timestamp: env.current_timestamp.as_u64(),
        // After ETH2.0, the DIFFICULTY opcode is changed to PREVRANDAO
        difficulty: h256_to_u256_be(env.current_random.unwrap_or_default()),
        gas_limit: env.current_gas_limit,
        last_hash: env.previous_hash.unwrap_or_default(),
        accumulated_gas_used: U256::zero(),
        base_gas_price,
        burnt_gas_price: base_gas_price, /* to align with ethereum, all
                                          * base gas price is burnt */
        transaction_hash,
        epoch_height: env.current_number.as_u64(), // set to current number
        transaction_epoch_bound: 100000,           /* set to default
                                                    * epoch bound */
        // pos_view, finalized_epoch is not set
        blob_gas_fee: calc_blob_gasprice(blob_gas),
        ..Default::default()
    }
}

fn calc_blob_gasprice(excess_blob_gas: u64) -> U256 {
    fn fake_exponential(factor: u64, numerator: u64, denominator: u64) -> u128 {
        assert_ne!(denominator, 0, "attempt to divide by zero");
        let factor = factor as u128;
        let numerator = numerator as u128;
        let denominator = denominator as u128;

        let mut i = 1;
        let mut output = 0;
        let mut numerator_accum = factor * denominator;
        while numerator_accum > 0 {
            output += numerator_accum;

            // Denominator is asserted as not zero at the start of the function.
            numerator_accum = (numerator_accum * numerator) / (denominator * i);
            i += 1;
        }
        output / denominator
    }

    const BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE: u64 = 5007716;
    const MIN_BLOB_GASPRICE: u64 = 1;
    fake_exponential(
        MIN_BLOB_GASPRICE,
        excess_blob_gas,
        BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
    )
    .into()
}

pub fn check_tx_bytes(
    txbytes: Option<&[u8]>, tx: &SignedTransaction,
) -> Result<(), TestErrorKind> {
    // Check whether the serialization result of the transaction
    // matches txbytes; if not, then fail the test
    let Some(txbytes) = txbytes else {
        return Ok(());
    };

    let raw_tx = rlp::encode(&tx.transaction.transaction);

    if raw_tx != txbytes {
        // trace!(
        //     "\tCheck txbytes failed expected vs actually: {} \n{} \n{}",
        //     self.name.clone(),
        //     hex::encode(txbytes.0.clone()),
        //     hex::encode(raw_tx)
        // );
        return Err(TestErrorKind::Internal(
            "txbytes check failed".to_string(),
        ));
    }

    Ok(())
}

pub fn check_tx_common(
    machine: &Machine, env: &Env, transaction: &SignedTransaction,
    verification: &VerificationConfig,
) -> Result<(), TransactionError> {
    let spec = machine
        .spec(env.number, env.epoch_height)
        .to_consensus_spec();
    let verify_mode = VerifyTxMode::Remote(&spec);

    let chain_id = AllChainID::new(
        env.chain_id[&Space::Native],
        env.chain_id[&Space::Ethereum],
    );

    verification.verify_transaction_common(
        &transaction.transaction,
        chain_id,
        env.epoch_height,
        &machine.params().transition_heights,
        verify_mode,
    )
}
