// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use super::super::super::db::COL_DELTA_TRIE;
use std::collections::HashMap;

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
            ),
            db: db,
            commit_lock: Mutex::new(AtomicCommit {
                row_number: RowNumber { value: row_number },
            }),
        }
    }

    /// ` test_net_version` is used to update the genesis author so that after
    /// resetting, the chain of the older version will be discarded
    pub fn initialize(
        &self, genesis_accounts: HashMap<Address, U256>,
        genesis_gas_limit: U256, test_net_version: Address,
    ) -> Block
    {
        let mut state = self.get_state_at(H256::default()).unwrap();

        for (addr, balance) in genesis_accounts {
            let account =
                Account::new_empty_with_balance(&addr, &balance, &0.into());
            state
                .set(
                    StorageKey::new_account_key(&addr).as_ref(),
                    encode(&account).as_ref(),
                )
                .unwrap();
        }

        let root = state.compute_state_root().unwrap();
        let genesis = Block {
            block_header: BlockHeaderBuilder::new()
                .with_deferred_state_root(root)
                .with_gas_limit(genesis_gas_limit)
                .with_author(test_net_version)
                .build(),
            transactions: Vec::new(),
        };
        debug!("Genesis Block:{:?} hash={:?}", genesis, genesis.hash());
        state.commit(genesis.block_header.hash()).unwrap();
        genesis
    }

    pub fn log_usage(&self) { self.delta_trie.log_usage(); }

    pub fn state_exists(&self, epoch_id: EpochId) -> bool {
        if let Ok(state) = self.get_state_at(epoch_id) {
            state.does_exist()
        } else {
            warn!("Fail to load state");
            false
        }
    }
}

impl StateManagerTrait for StateManager {
    fn from_snapshot(snapshot: &Snapshot) -> Self { unimplemented!() }

    fn make_snapshot(&self, epoch_id: EpochId) -> Snapshot { unimplemented!() }

    fn get_state_at(&self, epoch_id: EpochId) -> Result<State> {
        Ok(State::new(self, self.get_state_root_node_ref(epoch_id)?))
    }

    fn contains_state(&self, epoch_id: EpochId) -> bool {
        self.get_state_at(epoch_id).unwrap().does_exist()
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
use crate::{
    ext_db::SystemDB, snapshot::snapshot::Snapshot, statedb::StorageKey,
};
use cfx_types::{Address, H256, U256};
use kvdb::{DBTransaction, DBValue};
use primitives::{Account, Block, BlockHeaderBuilder, EpochId};
use rlp::encode;
use std::{
    io, str,
    sync::{Arc, Mutex, MutexGuard},
};
