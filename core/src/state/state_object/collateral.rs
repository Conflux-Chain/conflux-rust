use super::{substate::Substate, Spec, State, StateTracer};
use crate::{
    executive::internal_contract::storage_point_prop,
    state::trace::{
        trace_convert_stroage_points, trace_occupy_collateral,
        trace_refund_collateral,
    },
};
use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
use cfx_state::CollateralCheckResult;
use cfx_statedb::{global_params::*, Result as DbResult};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, Space, U256,
};

impl State {
    pub fn collateral_for_storage(&self, address: &Address) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(acc.collateral_for_storage())
    }

    pub fn token_collateral_for_storage(
        &self, address: &Address,
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(acc.token_collateral_for_storage())
    }

    pub fn available_storage_points_for_collateral(
        &self, address: &Address,
    ) -> DbResult<U256> {
        let acc = try_loaded!(self.read_native_account_lock(address));
        Ok(acc
            .sponsor_info()
            .storage_points
            .as_ref()
            .map(|points| points.unused)
            .unwrap_or_default())
    }

    /// Caller should make sure that staking_balance for this account is
    /// sufficient enough.
    pub fn add_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<U256> {
        noop_if!(by.is_zero());

        let storage_points_used = self
            .write_native_account_lock(&address)?
            .add_collateral_for_storage(by);
        *self.global_stat.val::<TotalStorage>() += *by - storage_points_used;
        *self.global_stat.val::<UsedStoragePoints>() += storage_points_used;
        Ok(storage_points_used)
    }

    pub fn sub_collateral_for_storage(
        &mut self, address: &Address, by: &U256,
    ) -> DbResult<U256> {
        noop_if!(by.is_zero());

        let collateral = self.token_collateral_for_storage(address)?;
        let refundable = if by > &collateral { &collateral } else { by };
        let burnt = *by - *refundable;
        let storage_points_refund = if !refundable.is_zero() {
            self.write_account_or_new_lock(&address.with_native_space())?
                .sub_collateral_for_storage(refundable)
        } else {
            U256::zero()
        };

        *self.global_stat.val::<TotalStorage>() -= *by - storage_points_refund;
        *self.global_stat.val::<UsedStoragePoints>() -= storage_points_refund;
        self.sub_total_issued(burnt);

        Ok(storage_points_refund)
    }

    /// Collects the cache (`ownership_change` in `OverlayAccount`) of storage
    /// change and write to substate.
    /// It is idempotent. But its execution is costly.
    pub fn collect_ownership_changed(
        &mut self, substate: &mut Substate,
    ) -> DbResult<()> {
        if let Some(checkpoint) = self.checkpoints.get_mut().last() {
            for address in
                checkpoint.keys().filter(|a| a.space == Space::Native)
            {
                if let Some(acc) = self
                    .cache
                    .get_mut()
                    .get_mut(address)
                    .filter(|x| x.is_dirty())
                    .and_then(|maybe_acc| maybe_acc.account.as_mut())
                {
                    acc.commit_ownership_change(&self.db, substate)?;
                }
            }
        }
        Ok(())
    }

    pub fn check_storage_limit(
        &self, original_sender: &Address, storage_limit: &U256, dry_run: bool,
    ) -> DbResult<CollateralCheckResult> {
        let collateral_for_storage =
            self.collateral_for_storage(original_sender)?;
        if collateral_for_storage > *storage_limit && !dry_run {
            Ok(CollateralCheckResult::ExceedStorageLimit {
                limit: *storage_limit,
                required: collateral_for_storage,
            })
        } else {
            Ok(CollateralCheckResult::Valid)
        }
    }

    // TODO: This function can only be called after VM execution. There are some
    // test cases breaks this assumption, which will be fixed in a separated PR.
    #[cfg(test)]
    pub fn collect_and_settle_collateral(
        &mut self, original_sender: &Address, storage_limit: &U256,
        substate: &mut Substate, tracer: &mut dyn StateTracer, spec: &Spec,
        dry_run: bool,
    ) -> DbResult<CollateralCheckResult>
    {
        self.collect_ownership_changed(substate)?;
        let res =
            settle_collateral_for_all(self, substate, tracer, spec, dry_run)?;
        Ok(if res.ok() {
            self.check_storage_limit(original_sender, storage_limit, dry_run)?
        } else {
            res
        })
    }

    fn initialize_cip107(
        &mut self, address: &Address,
    ) -> DbResult<(U256, U256)> {
        debug!("Check initialize CIP-107");

        let prop: U256 = self.get_system_storage(&storage_point_prop())?;
        let mut account =
            self.write_account_or_new_lock(&address.with_native_space())?;
        noop_if!(account.is_cip_107_initialized());

        let (from_balance, from_collateral) = account.initialize_cip107(prop);
        std::mem::drop(account);

        self.add_converted_storage_point(from_balance, from_collateral);
        Ok((from_balance, from_collateral))
    }
}

/// Charges or refund storage collateral and update `total_storage_tokens`.
fn settle_collateral_for_address(
    state: &mut State, addr: &Address, substate: &Substate,
    tracer: &mut dyn StateTracer, spec: &Spec, dry_run: bool,
) -> DbResult<CollateralCheckResult>
{
    let addr_with_space = addr.with_native_space();
    let (inc_collaterals, sub_collaterals) =
        substate.get_collateral_change(addr);
    let (inc, sub) = (
        *DRIPS_PER_STORAGE_COLLATERAL_UNIT * inc_collaterals,
        *DRIPS_PER_STORAGE_COLLATERAL_UNIT * sub_collaterals,
    );

    let is_contract = state.is_contract_with_code(&addr_with_space)?;

    // Initialize CIP-107
    if spec.cip107
        && addr.is_contract_address()
        && (!sub.is_zero() || !inc.is_zero())
    {
        let (from_balance, from_collateral) = state.initialize_cip107(addr)?;
        trace_convert_stroage_points(
            tracer,
            *addr,
            from_balance,
            from_collateral,
        );
    }

    if !sub.is_zero() {
        let storage_points_refund =
            state.sub_collateral_for_storage(addr, &sub)?;
        trace_refund_collateral(tracer, *addr, sub - storage_points_refund);
    }
    if !inc.is_zero() && !dry_run {
        let balance = if is_contract {
            state.sponsor_balance_for_collateral(addr)?
                + state.available_storage_points_for_collateral(addr)?
        } else {
            state.balance(&addr_with_space)?
        };
        // sponsor_balance is not enough to cover storage incremental.
        if inc > balance {
            return Ok(CollateralCheckResult::NotEnoughBalance {
                required: inc,
                got: balance,
            });
        }

        let storage_points_used =
            state.add_collateral_for_storage(addr, &inc)?;
        trace_occupy_collateral(tracer, *addr, inc - storage_points_used);
    }
    Ok(CollateralCheckResult::Valid)
}

/// Charge and refund all the storage collaterals.
/// The suicided addresses are skimmed because their collateral have been
/// checked out. This function should only be called in post-processing
/// of a transaction.
pub fn settle_collateral_for_all(
    state: &mut State, substate: &Substate, tracer: &mut dyn StateTracer,
    spec: &Spec, dry_run: bool,
) -> DbResult<CollateralCheckResult>
{
    for address in substate.keys_for_collateral_changed().iter() {
        let res = settle_collateral_for_address(
            state, &address, substate, tracer, spec, dry_run,
        )?;
        if !res.ok() {
            return Ok(res);
        }
    }
    Ok(CollateralCheckResult::Valid)
}
