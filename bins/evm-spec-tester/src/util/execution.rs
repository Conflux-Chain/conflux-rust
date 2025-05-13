use cfx_executor::{
    executive::{ChargeCollateral, TransactOptions, TransactSettings},
    state::State,
};
use cfx_rpc_eth_types::{
    AccountOverride, AccountStateOverrideMode, StateOverride,
};
use cfx_statedb::StateDb;
use cfx_types::{u256_to_h256_be, Address, Space, H256, U256, U64};
use eest_types::AccountInfo;
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
