use super::pool_metrics::pool_inner_metrics::TX_POOL_GET_STATE_TIMER;
use cfx_executor::state::State;
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, AddressWithSpace, U256};
use metrics::MeterTimer;
use primitives::SponsorInfo;
use std::sync::Arc;

pub struct StateProvider {
    state: Arc<State>,
}

impl StateProvider {
    pub fn new(state: Arc<State>) -> Self { StateProvider { state } }

    pub fn get_nonce_and_balance(
        &self, address: &AddressWithSpace,
    ) -> DbResult<(U256, U256)> {
        let _timer = MeterTimer::time_func(TX_POOL_GET_STATE_TIMER.as_ref());
        Ok((self.state.nonce(address)?, self.state.balance(address)?))
    }

    pub fn get_nonce(&self, address: &AddressWithSpace) -> DbResult<U256> {
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
        self.state.check_contract_whitelist(contract_address, user)
    }
}
