use super::State;
use cfx_parameters::genesis::{
    genesis_contract_address_four_year, genesis_contract_address_two_year,
};
use cfx_statedb::{global_params::*, Result as DbResult};
use cfx_types::{Address, AddressSpaceUtil, U256};

impl State {
    pub fn total_issued_tokens(&self) -> U256 {
        self.global_stat.get::<TotalIssued>()
    }

    /// Maintain `total_issued_tokens`.
    pub fn add_total_issued(&mut self, v: U256) {
        *self.global_stat.val::<TotalIssued>() += v;
    }

    /// Maintain `total_issued_tokens`. This is only used in the extremely
    /// unlikely case that there are a lot of partial invalid blocks.
    pub fn sub_total_issued(&mut self, v: U256) {
        *self.global_stat.val::<TotalIssued>() =
            self.global_stat.refr::<TotalIssued>().saturating_sub(v);
    }

    pub fn add_total_pos_staking(&mut self, v: U256) {
        *self.global_stat.val::<TotalPosStaking>() += v;
    }

    pub fn add_total_evm_tokens(&mut self, v: U256) {
        *self.global_stat.val::<TotalEvmToken>() += v;
    }

    pub fn sub_total_evm_tokens(&mut self, v: U256) {
        *self.global_stat.val::<TotalEvmToken>() =
            self.global_stat.refr::<TotalEvmToken>().saturating_sub(v);
    }

    pub fn total_staking_tokens(&self) -> U256 {
        self.global_stat.get::<TotalStaking>()
    }

    pub fn total_storage_tokens(&self) -> U256 {
        self.global_stat.get::<TotalStorage>()
    }

    pub fn total_espace_tokens(&self) -> U256 {
        self.global_stat.get::<TotalEvmToken>()
    }

    pub fn used_storage_points(&self) -> U256 {
        self.global_stat.get::<UsedStoragePoints>()
    }

    pub fn converted_storage_points(&self) -> U256 {
        self.global_stat.get::<ConvertedStoragePoints>()
    }

    pub fn total_pos_staking_tokens(&self) -> U256 {
        self.global_stat.get::<TotalPosStaking>()
    }

    pub fn sub_total_pos_staking(&mut self, v: U256) {
        *self.global_stat.val::<TotalPosStaking>() =
            self.global_stat.refr::<TotalPosStaking>().saturating_sub(v)
    }

    pub fn total_circulating_tokens(&self) -> DbResult<U256> {
        Ok(self.total_issued_tokens()
            - self.balance(&Address::zero().with_native_space())?
            - self.balance(&genesis_contract_address_four_year())?
            - self.balance(&genesis_contract_address_two_year())?)
    }

    pub fn add_converted_storage_point(
        &mut self, from_balance: U256, from_collateral: U256,
    ) {
        *self.global_stat.val::<TotalIssued>() -=
            from_balance + from_collateral;
        *self.global_stat.val::<TotalStorage>() -= from_collateral;
        *self.global_stat.val::<UsedStoragePoints>() += from_collateral;
        *self.global_stat.val::<ConvertedStoragePoints>() +=
            from_balance + from_collateral;
    }
}
