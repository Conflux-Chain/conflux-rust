// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

use crate::Executor;
use anyhow::{format_err, Result};
use cached_pos_ledger_db::CachedPosLedgerDB;
use consensus_types::db::FakeLedgerBlockDB;
use diem_crypto::{hash::PRE_GENESIS_BLOCK_ID, HashValue};
use diem_logger::prelude::*;
use diem_state_view::{StateView, StateViewId};
use diem_types::{
    account_address::AccountAddress,
    block_info::{
        BlockInfo, PivotBlockDecision, GENESIS_EPOCH, GENESIS_ROUND,
        GENESIS_TIMESTAMP_USECS,
    },
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    term_state::NodeID,
    transaction::Transaction,
};
use executor_types::BlockExecutor;
use pow_types::FakePowHandler;
use std::{collections::btree_map::BTreeMap, sync::Arc};
use storage_interface::{DbReaderWriter, TreeState};

/// If the database has not been bootstrapped yet, commit the genesis
/// transaction. Returns Ok(true) if committed, Ok(false) if already
/// bootstrapped.
pub fn maybe_bootstrap(
    db: &DbReaderWriter, genesis_txn: &Transaction,
    genesis_pivot_decision: Option<PivotBlockDecision>, initial_seed: Vec<u8>,
    initial_nodes: Vec<(NodeID, u64)>,
    initial_committee: Vec<(AccountAddress, u64)>,
) -> Result<bool> {
    let tree_state = db.reader.get_latest_tree_state()?;
    // If the DB already has transactions, it's already bootstrapped.
    if tree_state.num_transactions != 0 {
        diem_info!("DB already bootstrapped, skipping genesis.");
        return Ok(false);
    }
    diem_debug!(
        "genesis_txn={:?}, initial_nodes={:?} ",
        genesis_txn,
        initial_nodes,
    );

    let committer = calculate_genesis(
        db,
        tree_state,
        genesis_txn,
        genesis_pivot_decision,
        initial_seed,
        initial_nodes,
        initial_committee,
    )?;
    committer.commit()?;
    Ok(true)
}

pub struct GenesisCommitter {
    executor: Executor,
    ledger_info_with_sigs: LedgerInfoWithSignatures,
}

impl GenesisCommitter {
    pub fn new(
        executor: Executor, ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) -> Result<Self> {
        Ok(Self {
            executor,
            ledger_info_with_sigs,
        })
    }

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

pub fn calculate_genesis(
    db: &DbReaderWriter, tree_state: TreeState, genesis_txn: &Transaction,
    genesis_pivot_decision: Option<PivotBlockDecision>, initial_seed: Vec<u8>,
    initial_nodes: Vec<(NodeID, u64)>,
    initial_committee: Vec<(AccountAddress, u64)>,
) -> Result<GenesisCommitter> {
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
    let executor = Executor::new(
        db_with_cache,
        // This will not be used in genesis execution.
        Arc::new(FakePowHandler {}),
        Arc::new(FakeLedgerBlockDB {}),
    );

    let block_id = HashValue::zero();
    // Deliberate product decision: Conflux PoS does not support Diem's
    // non-zero genesis recovery path (bootstrapping from a mid-chain
    // snapshot). This assertion ensures we fail explicitly rather than
    // silently producing incorrect state if this assumption is violated.
    assert_eq!(
        genesis_version, 0,
        "Conflux PoS only supports genesis at version 0"
    );
    let epoch = GENESIS_EPOCH;

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
    let timestamp_usecs = GENESIS_TIMESTAMP_USECS;

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
        "Genesis calculated: ledger_info_with_sigs {:?}",
        committer.ledger_info_with_sigs,
    );
    Ok(committer)
}

fn genesis_block_id() -> HashValue { HashValue::zero() }
