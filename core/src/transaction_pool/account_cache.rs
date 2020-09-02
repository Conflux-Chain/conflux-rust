use crate::{
    state::State,
    transaction_pool::transaction_pool_inner::TX_POOL_GET_STATE_TIMER,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, U256};
use metrics::MeterTimer;
use primitives::SponsorInfo;
use std::sync::Arc;

// TODO: perhaps rename to StateWrapper.
pub struct AccountCache {
    state: Arc<State>,
}

impl AccountCache {
    pub fn new(state: Arc<State>) -> Self { AccountCache { state } }

    pub fn get_nonce_and_balance(
        &self, address: &Address,
    ) -> DbResult<(U256, U256)> {
        let _timer = MeterTimer::time_func(TX_POOL_GET_STATE_TIMER.as_ref());
        Ok((self.state.nonce(address)?, self.state.balance(address)?))
    }

    pub fn get_nonce(&self, address: &Address) -> DbResult<U256> {
        self.state.nonce(address)
    }

    pub fn get_sponsor_info(
        &self, contract_address: &Address,
    ) -> DbResult<Option<SponsorInfo>> {
        self.state.sponsor_info(contract_address)
    }

    pub fn check_commission_privilege(
        &self, contract_address: &Address, user: &Address,
    ) -> DbResult<bool> {
        self.state
            .check_commission_privilege(contract_address, user)
    }
}
