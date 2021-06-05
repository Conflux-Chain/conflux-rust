// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait SubstateTrait {
    fn get_collateral_change(&self, address: &Address) -> (u64, u64);

    fn logs(&self) -> &[LogEntry];

    fn logs_mut(&mut self) -> &mut Vec<LogEntry>;

    fn storage_at(
        &self, state: &dyn StateOpsTrait, address: &Address, key: &[u8],
    ) -> DbResult<U256>;

    fn set_storage(
        &mut self, state: &mut dyn StateOpsTrait, address: &Address,
        key: Vec<u8>, value: U256, owner: Address,
    ) -> DbResult<()>;

    fn record_storage_occupy(&mut self, address: &Address, collaterals: u64);

    fn touched(&mut self) -> &mut HashSet<Address>;

    fn sstore_clears_refund(&self) -> i128;

    fn sstore_clears_refund_mut(&mut self) -> &mut i128;

    fn contracts_created(&self) -> &[Address];
    fn contracts_created_mut(&mut self) -> &mut Vec<Address>;

    fn record_storage_release(&mut self, address: &Address, collaterals: u64);

    fn keys_for_collateral_changed(&self) -> HashSet<&Address>;

    fn suicides(&self) -> &HashSet<Address>;

    fn suicides_mut(&mut self) -> &mut HashSet<Address>;

    fn contract_in_creation(&self) -> Option<&Address>;
}

pub trait SubstateMngTrait: SubstateTrait {
    fn accrue(&mut self, s: Self);

    fn new() -> Self;

    fn update_contract_in_creation_call(
        self, parent_contract_in_creation: Option<Address>,
        is_internal_contract: bool,
    ) -> Self;

    fn set_contract_in_creation_create(
        self, contract_in_creation: Address,
    ) -> Self;
}

use crate::state_trait::StateOpsTrait;
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, U256};
use primitives::LogEntry;
use std::collections::HashSet;
