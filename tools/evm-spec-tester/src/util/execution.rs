use cfx_executor::{
    executive::{ChargeCollateral, TransactOptions, TransactSettings},
    machine::Machine,
    state::State,
};
use cfx_rpc_eth_types::{
    AccountOverride, AccountStateOverrideMode, Bytes, StateOverride,
};
use cfx_statedb::StateDb;
use cfx_types::{u256_to_h256_be, Address, AllChainID, Space, H256, U256, U64};
use cfx_vm_types::Env;
use cfxcore::verification::{VerificationConfig, VerifyTxMode};
use eest_types::AccountInfo;
use primitives::{
    transaction::{eth_transaction::eip155_signature, TransactionError},
    SignedTransaction,
};
use std::collections::HashMap;

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

pub fn calc_blob_gasprice(excess_blob_gas: u64) -> U256 {
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

// 1. Check if the input bytes is a rlp list
// 2. If it is, rlp decode the raw tx
// 3. Check the v value (the third from the last), if it is bigger than 28, then
//    it include the chainId info
pub(crate) fn extract_155_chain_id_from_raw_tx(
    raw_tx: &Option<Bytes>,
) -> Option<u64> {
    match raw_tx {
        Some(raw_tx) => match is_rlp_list(&raw_tx.0) {
            true => {
                let rlp_list = rlp::Rlp::new(&raw_tx.0);
                let item_count = rlp_list.item_count().ok()?;
                let v = rlp_list.val_at::<u64>(item_count - 3).ok()?;
                eip155_signature::extract_chain_id_from_legacy_v(v)
            }
            false => None, // not a 155 tx
        },
        None => None,
    }
}

fn is_rlp_list(raw: &[u8]) -> bool { !raw.is_empty() && raw[0] >= 0xc0 }

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
