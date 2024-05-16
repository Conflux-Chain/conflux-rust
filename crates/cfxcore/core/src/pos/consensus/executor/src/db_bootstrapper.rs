// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

use crate::{vm::VMExecutor, Executor};
use anyhow::{ensure, format_err, Result};
use cached_pos_ledger_db::CachedPosLedgerDB;
use consensus_types::db::FakeLedgerBlockDB;
use diem_crypto::{hash::PRE_GENESIS_BLOCK_ID, HashValue};
use diem_logger::prelude::*;
use diem_state_view::{StateView, StateViewId};
use diem_types::{
    access_path::AccessPath,
    account_address::AccountAddress,
    account_config::diem_root_address,
    block_info::{
        BlockInfo, PivotBlockDecision, GENESIS_EPOCH, GENESIS_ROUND,
        GENESIS_TIMESTAMP_USECS,
    },
    diem_timestamp::DiemTimestampResource,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    on_chain_config::{config_address, ConfigurationResource},
    term_state::NodeID,
    transaction::Transaction,
    waypoint::Waypoint,
};
use executor_types::BlockExecutor;
use move_core_types::move_resource::MoveResource;
use pow_types::FakePowHandler;
use std::{collections::btree_map::BTreeMap, sync::Arc};
use storage_interface::{
    state_view::VerifiedStateView, DbReaderWriter, TreeState,
};

pub fn generate_waypoint<V: VMExecutor>(
    db: &DbReaderWriter, genesis_txn: &Transaction,
) -> Result<Waypoint> {
    let tree_state = db.reader.get_latest_tree_state()?;

    // TODO(lpl): initial nodes are not passed.
    // genesis ledger info (including pivot decision) is not used.
    let committer = calculate_genesis::<V>(
        db,
        tree_state,
        genesis_txn,
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    Ok(committer.waypoint)
}

/// If current version + 1 != waypoint.version(), return Ok(false) indicating
/// skipping the txn. otherwise apply the txn and commit it if the result
/// matches the waypoint. Returns Ok(true) if committed otherwise Err.
pub fn maybe_bootstrap<V: VMExecutor>(
    db: &DbReaderWriter, genesis_txn: &Transaction, waypoint: Waypoint,
    genesis_pivot_decision: Option<PivotBlockDecision>, initial_seed: Vec<u8>,
    initial_nodes: Vec<(NodeID, u64)>,
    initial_committee: Vec<(AccountAddress, u64)>,
) -> Result<bool> {
    let tree_state = db.reader.get_latest_tree_state()?;
    // if the waypoint is not targeted with the genesis txn, it may be either
    // already bootstrapped, or aiming for state sync to catch up.
    if tree_state.num_transactions != waypoint.version() {
        diem_info!(waypoint = %waypoint, "Skip genesis txn.");
        return Ok(false);
    }
    diem_debug!(
        "genesis_txn={:?}, initial_nodes={:?} ",
        genesis_txn,
        initial_nodes,
    );

    let committer = calculate_genesis::<V>(
        db,
        tree_state,
        genesis_txn,
        genesis_pivot_decision,
        initial_seed,
        initial_nodes,
        initial_committee,
    )?;
    ensure!(
        waypoint == committer.waypoint(),
        "Waypoint verification failed. Expected {:?}, got {:?}.",
        waypoint,
        committer.waypoint(),
    );
    committer.commit()?;
    Ok(true)
}

pub struct GenesisCommitter<V: VMExecutor> {
    executor: Executor<V>,
    ledger_info_with_sigs: LedgerInfoWithSignatures,
    waypoint: Waypoint,
}

impl<V: VMExecutor> GenesisCommitter<V> {
    pub fn new(
        executor: Executor<V>, ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) -> Result<Self> {
        let waypoint =
            Waypoint::new_epoch_boundary(ledger_info_with_sigs.ledger_info())?;

        Ok(Self {
            executor,
            ledger_info_with_sigs,
            waypoint,
        })
    }

    pub fn waypoint(&self) -> Waypoint { self.waypoint }

    pub fn commit(self) -> Result<()> {
        self.executor.commit_blocks(
            vec![genesis_block_id()],
            self.ledger_info_with_sigs,
        )?;
        diem_info!("Genesis commited.");
        // DB bootstrapped, avoid anything that could fail after this.

        Ok(())
    }
}

pub fn calculate_genesis<V: VMExecutor>(
    db: &DbReaderWriter, tree_state: TreeState, genesis_txn: &Transaction,
    genesis_pivot_decision: Option<PivotBlockDecision>, initial_seed: Vec<u8>,
    initial_nodes: Vec<(NodeID, u64)>,
    initial_committee: Vec<(AccountAddress, u64)>,
) -> Result<GenesisCommitter<V>> {
    // DB bootstrapper works on either an empty transaction accumulator or an
    // existing block chain. In the very extreme and sad situation of losing
    // quorum among validators, we refer to the second use case said above.
    let genesis_version = tree_state.num_transactions;
    let db_with_cache = Arc::new(CachedPosLedgerDB::new_on_unbootstrapped_db(
        db.clone(),
        tree_state,
        initial_seed,
        initial_nodes,
        initial_committee,
        genesis_pivot_decision.clone(),
    ));
    let executor = Executor::<V>::new(
        db_with_cache,
        // This will not be used in genesis execution.
        Arc::new(FakePowHandler {}),
        Arc::new(FakeLedgerBlockDB {}),
    );

    let block_id = HashValue::zero();
    let epoch = if genesis_version == 0 {
        GENESIS_EPOCH
    } else {
        let executor_trees =
            executor.get_executed_trees(*PRE_GENESIS_BLOCK_ID)?;
        let state_view = executor.get_executed_state_view(
            StateViewId::Miscellaneous,
            &executor_trees,
        );
        get_state_epoch(&state_view)?
    };

    // Create a block with genesis_txn being the only txn. Execute it then
    // commit it immediately.
    let result = executor.execute_block(
        (block_id, vec![genesis_txn.clone()]),
        *PRE_GENESIS_BLOCK_ID,
        // Use `catch_up_mode=false` for genesis to calculate VDF output.
        false,
    )?;

    let root_hash = result.root_hash();
    let next_epoch_state = result.epoch_state().as_ref().ok_or_else(|| {
        format_err!("Genesis transaction must emit a epoch change.")
    })?;
    let executed_trees = executor.get_executed_trees(block_id)?;
    let state_view = executor
        .get_executed_state_view(StateViewId::Miscellaneous, &executed_trees);
    diem_debug!(
        "after genesis: epoch_state={:?}, pos_state={:?}",
        next_epoch_state,
        state_view.pos_state().epoch_state()
    );
    let timestamp_usecs = if genesis_version == 0 {
        // TODO(aldenhu): fix existing tests before using real timestamp and
        // check on-chain epoch.
        GENESIS_TIMESTAMP_USECS
    } else {
        let next_epoch = epoch
            .checked_add(1)
            .ok_or_else(|| format_err!("integer overflow occurred"))?;

        ensure!(
            next_epoch == get_state_epoch(&state_view)?,
            "Genesis txn didn't bump epoch."
        );
        get_state_timestamp(&state_view)?
    };

    let ledger_info_with_sigs = LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(
                epoch,
                GENESIS_ROUND,
                block_id,
                root_hash,
                genesis_version,
                timestamp_usecs,
                Some(next_epoch_state.clone()),
                genesis_pivot_decision,
            ),
            HashValue::zero(), /* consensus_data_hash */
        ),
        BTreeMap::default(), /* signatures */
    );

    let committer = GenesisCommitter::new(executor, ledger_info_with_sigs)?;
    diem_info!(
        "Genesis calculated: ledger_info_with_sigs {:?}, waypoint {:?}",
        committer.ledger_info_with_sigs,
        committer.waypoint,
    );
    Ok(committer)
}

fn get_state_timestamp(state_view: &VerifiedStateView) -> Result<u64> {
    let rsrc_bytes = &state_view
        .get(&AccessPath::new(
            diem_root_address(),
            DiemTimestampResource::resource_path(),
        ))?
        .ok_or_else(|| format_err!("DiemTimestampResource missing."))?;
    let rsrc = bcs::from_bytes::<DiemTimestampResource>(&rsrc_bytes)?;
    Ok(rsrc.diem_timestamp.microseconds)
}

fn get_state_epoch(state_view: &VerifiedStateView) -> Result<u64> {
    let rsrc_bytes = &state_view
        .get(&AccessPath::new(
            config_address(),
            ConfigurationResource::resource_path(),
        ))?
        .ok_or_else(|| format_err!("ConfigurationResource missing."))?;
    let rsrc = bcs::from_bytes::<ConfigurationResource>(&rsrc_bytes)?;
    Ok(rsrc.epoch())
}

fn genesis_block_id() -> HashValue { HashValue::zero() }
