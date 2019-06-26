// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use super::super::super::db::COL_DELTA_TRIE;

// FIXME: commit is per DeltaMPT.
#[derive(Default)]
pub struct AtomicCommit {
    pub row_number: RowNumber,
}

pub struct AtomicCommitTransaction<'a> {
    pub info: MutexGuard<'a, AtomicCommit>,
    pub transaction: DBTransaction,
}

pub struct StateManager {
    delta_trie: MultiVersionMerklePatriciaTrie,
    pub db: Arc<SystemDB>,
    commit_lock: Mutex<AtomicCommit>,
    pub number_commited_nodes: AtomicUsize,
}

impl StateManager {
    pub(super) fn get_delta_trie(&self) -> &MultiVersionMerklePatriciaTrie {
        &self.delta_trie
    }

    pub fn start_commit(&self) -> AtomicCommitTransaction {
        AtomicCommitTransaction {
            info: self.commit_lock.lock().unwrap(),
            transaction: self.db.key_value().transaction(),
        }
    }

    fn load_state_root_node_ref_from_db(
        &self, epoch_id: EpochId,
    ) -> Result<Option<NodeRefDeltaMpt>> {
        let db_key_result = Self::parse_row_number(
            self.db.key_value().get(
                COL_DELTA_TRIE,
                [
                    "state_root_db_key_for_epoch_id_".as_bytes(),
                    epoch_id.as_ref(),
                ]
                .concat()
                .as_slice(),
            ),
        )?;
        match db_key_result {
            Some(db_key) => {
                Ok(Some(self.delta_trie.loaded_root_at_epoch(epoch_id, db_key)))
            }
            None => Ok(None),
        }
    }

    fn get_state_root_node_ref(
        &self, epoch_id: EpochId,
    ) -> Result<Option<NodeRefDeltaMpt>> {
        let node_ref = self.delta_trie.get_root_at_epoch(epoch_id);
        if node_ref.is_none() {
            self.load_state_root_node_ref_from_db(epoch_id)
        } else {
            Ok(node_ref)
        }
    }

    // TODO(ming): Should prevent from committing at existing epoch because
    // otherwise the overwritten trie nodes can not be reachable from db.
    // The current codebase overwrites because it didn't check if the state
    // root is already computed, which should eventually be optimized out.
    // TODO(ming): Use self.get_state_root_node_ref(epoch_id).
    pub(super) fn mpt_commit_state_root(
        &self, epoch_id: EpochId, root_node: Option<NodeRefDeltaMpt>,
    ) {
        match root_node {
            None => {}
            Some(node) => {
                // Debugging log.
                info!("State root committed for epoch {:?}", epoch_id);
                self.delta_trie.set_epoch_root(epoch_id, node.clone())
            }
        }
    }

    fn parse_row_number(
        x: io::Result<Option<DBValue>>,
    ) -> Result<Option<RowNumberUnderlyingType>> {
        Ok(match x?.as_ref() {
            None => None,
            Some(row_number_bytes) => Some(
                unsafe { str::from_utf8_unchecked(row_number_bytes.as_ref()) }
                    .parse::<RowNumberUnderlyingType>()?,
            ),
        })
    }

    pub fn new(db: Arc<SystemDB>, conf: StorageConfiguration) -> Self {
        let row_number = Self::parse_row_number(
            db.key_value()
                .get(COL_DELTA_TRIE, "last_row_number".as_bytes()),
        )
        // unwrap() on new is fine.
        .unwrap()
        .unwrap_or_default();
        debug!("Storage conf {:?}", conf);

        Self {
            delta_trie: MultiVersionMerklePatriciaTrie::new(
                db.key_value().clone(),
                conf,
                MultiVersionMerklePatriciaTrie::padding(
                    MERKLE_NULL_NODE,
                    MERKLE_NULL_NODE,
                ),
            ),
            db: db,
            commit_lock: Mutex::new(AtomicCommit {
                row_number: RowNumber { value: row_number },
            }),
            number_commited_nodes: Default::default(),
        }
    }

    /// ` test_net_version` is used to update the genesis author so that after
    /// resetting, the chain of the older version will be discarded
    pub fn initialize(
        &self, genesis_accounts: HashMap<Address, U256>,
        genesis_gas_limit: U256, test_net_version: Address,
    ) -> Block
    {
        let mut state = StateDb::new(self.get_state_for_genesis_write());

        for (addr, balance) in genesis_accounts {
            let account =
                Account::new_empty_with_balance(&addr, &balance, &0.into());
            state.set(&state.account_key(&addr), &account).unwrap();
        }

        let state_root = state.compute_state_root().unwrap();
        let mut genesis = Block::new(
            BlockHeaderBuilder::new()
                .with_deferred_state_root(state_root)
                .with_gas_limit(genesis_gas_limit)
                .with_author(test_net_version)
                .build(),
            Vec::new(),
        );
        genesis.block_header.compute_hash();
        debug!("Genesis Block:{:?} hash={:?}", genesis, genesis.hash());
        state.commit(genesis.block_header.hash()).unwrap();
        genesis
    }

    pub fn log_usage(&self) {
        self.delta_trie.log_usage();
        info!(
            "number of nodes committed to db {}",
            self.number_commited_nodes.load(Ordering::Relaxed),
        );
    }

    // FIXME: remove debug code.
    pub unsafe fn get_state_readonly_assumed_existence(
        &self, epoch_id: EpochId,
    ) -> Result<State> {
        let maybe_state = self.get_state_no_commit(epoch_id)?;
        Ok(match maybe_state {
            Some(state) => state,
            None => {
                warn!("state doesn't exist at epoch {:?}.", epoch_id);
                // FIXME: Error were found in
                // FIXME: transaction_pool/mod.rs#insert_new_transactions
                // FIXME: transactiongen/src/lib.rs#generate_transactions
                // FIXME: and consensus/mod.rs#get_balance, where the obtained
                // FIXME: state doesn't exist. The bug should be
                // FIXME: fixed and the debugging code here should be removed.
                self.get_state_for_genesis_write()
            }
        })
    }
}

impl StateManagerTrait for StateManager {
    fn from_snapshot(snapshot: &Snapshot) -> Self { unimplemented!() }

    fn make_snapshot(&self, epoch_id: EpochId) -> Snapshot { unimplemented!() }

    fn get_state_no_commit(&self, epoch_id: EpochId) -> Result<Option<State>> {
        Ok(self
            .get_state_root_node_ref(epoch_id)?
            .map(|root_node_ref| State::new(self, Some(root_node_ref))))
    }

    fn get_state_at(&self, epoch_id: EpochId) -> Result<State> {
        // FIXME: only allow existing epoch id and H256::Default().
        Ok(State::new(self, self.get_state_root_node_ref(epoch_id)?))
    }

    fn get_state_for_genesis_write(&self) -> State { State::new(self, None) }

    fn get_state_for_next_epoch(
        &self, parent_epoch_id: EpochId,
    ) -> Result<Option<State>> {
        // FIXME: deal with snapshot shift.
        Ok(self
            .get_state_root_node_ref(parent_epoch_id)?
            .map(|root_node_ref| State::new(self, Some(root_node_ref))))
    }

    fn contains_state(&self, epoch_id: EpochId) -> bool {
        if let Ok(root_node) = self.get_state_root_node_ref(epoch_id) {
            root_node.is_some()
        } else {
            warn!("Fail to load state for epoch {}", epoch_id);
            false
        }
    }

    fn drop_state_outside(&self, epoch_id: EpochId) { unimplemented!() }
}

use super::{
    super::{state::*, state_manager::*},
    errors::*,
    multi_version_merkle_patricia_trie::{
        merkle_patricia_trie::NodeRefDeltaMpt, row_number::*, *,
    },
};
use crate::{ext_db::SystemDB, snapshot::snapshot::Snapshot, statedb::StateDb};
use cfx_types::{Address, U256};
use kvdb::{DBTransaction, DBValue};
use primitives::{
    Account, Block, BlockHeaderBuilder, EpochId, MERKLE_NULL_NODE,
};
use std::{
    collections::HashMap,
    io, str,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
};
