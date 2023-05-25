// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// pub trait StateTrait: CheckpointTrait {
//     type Substate;
//     type Spec;

//     /// Collects the cache (`ownership_change` in `OverlayAccount`) of storage
//     /// change and write to substate.
//     /// It is idempotent. But its execution is costly.
//     fn collect_ownership_changed(
//         &mut self, substate: &mut Self::Substate,
//     ) -> DbResult<()>;

//     /// Charge and refund all the storage collaterals.
//     /// The suicided addresses are skimmed because their collateral have been
//     /// checked out. This function should only be called in post-processing
//     /// of a transaction.
//     fn settle_collateral_for_all(
//         &mut self, substate: &Self::Substate, tracer: &mut dyn StateTracer,
//         spec: &Self::Spec, dry_run_no_charge: bool,
//     ) -> DbResult<CollateralCheckResult>;

//     // FIXME: add doc string.
//     fn collect_and_settle_collateral(
//         &mut self, original_sender: &Address, storage_limit: &U256,
//         substate: &mut Self::Substate, tracer: &mut dyn StateTracer,
//         spec: &Self::Spec, dry_run_no_charge: bool,
//     ) -> DbResult<CollateralCheckResult>;

//     // TODO: maybe we can find a better interface for doing the suicide
//     // post-processing.
//     fn record_storage_and_whitelist_entries_release(
//         &mut self, address: &Address, substate: &mut Self::Substate,
//     ) -> DbResult<()>;

//     fn compute_state_root(
//         &mut self, debug_record: Option<&mut ComputeEpochDebugRecord>,
//     ) -> DbResult<StateRootWithAuxInfo>;

//     fn commit(
//         &mut self, epoch_id: EpochId,
//         debug_record: Option<&mut ComputeEpochDebugRecord>,
//     ) -> DbResult<StateRootWithAuxInfo>;
// }

// pub trait CheckpointTrait {
//     /// Create a recoverable checkpoint of this state. Return the checkpoint
//     /// index. The checkpoint records any old value which is alive at the
//     /// creation time of the checkpoint and updated after that and before
//     /// the creation of the next checkpoint.
//     fn checkpoint(&mut self) -> usize;

//     /// Merge last checkpoint with previous.
//     /// Caller should make sure the function
//     /// `collect_ownership_changed()` was called before calling
//     /// this function.
//     fn discard_checkpoint(&mut self);

//     /// Revert to the last checkpoint and discard it.
//     fn revert_to_checkpoint(&mut self);
// }

// use super::CollateralCheckResult;
// use crate::tracer::StateTracer;
// use cfx_internal_common::{
//     debug::ComputeEpochDebugRecord, StateRootWithAuxInfo,
// };
// use cfx_statedb::Result as DbResult;
// use cfx_types::{Address, U256};
// use primitives::EpochId;
