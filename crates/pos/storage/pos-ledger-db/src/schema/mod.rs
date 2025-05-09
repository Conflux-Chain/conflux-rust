// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! This module defines representation of Diem core data structures at physical
//! level via schemas that implement [`schemadb::schema::Schema`].
//!
//! All schemas are `pub(crate)` so not shown in rustdoc, refer to the source
//! code to see details.

use anyhow::{ensure, Result};

use schemadb::ColumnFamilyName;

pub(crate) mod block_by_epoch_and_round;
pub(crate) mod committed_block;
pub(crate) mod committed_block_by_view;
pub(crate) mod epoch_by_version;
pub(crate) mod event;
pub(crate) mod event_accumulator;
pub(crate) mod event_by_key;
pub(crate) mod event_by_version;
pub(crate) mod jellyfish_merkle_node;
pub(crate) mod ledger_counters;
pub(crate) mod ledger_info;
pub(crate) mod ledger_info_by_block;
pub(crate) mod ledger_info_by_voted_block;
pub(crate) mod pos_state;
pub(crate) mod reward_event;
pub(crate) mod stale_node_index;
pub(crate) mod transaction;
pub(crate) mod transaction_accumulator;
pub(crate) mod transaction_by_account;
pub(crate) mod transaction_info;

pub const EPOCH_BY_VERSION_CF_NAME: ColumnFamilyName = "epoch_by_version";
pub const EVENT_ACCUMULATOR_CF_NAME: ColumnFamilyName = "event_accumulator";
pub const EVENT_BY_KEY_CF_NAME: ColumnFamilyName = "event_by_key";
pub const EVENT_BY_VERSION_CF_NAME: ColumnFamilyName = "event_by_version";
pub const EVENT_CF_NAME: ColumnFamilyName = "event";
pub const JELLYFISH_MERKLE_NODE_CF_NAME: ColumnFamilyName =
    "jellyfish_merkle_node";
pub const LEDGER_COUNTERS_CF_NAME: ColumnFamilyName = "ledger_counters";
pub const STALE_NODE_INDEX_CF_NAME: ColumnFamilyName = "stale_node_index";
pub const TRANSACTION_CF_NAME: ColumnFamilyName = "transaction";
pub const TRANSACTION_ACCUMULATOR_CF_NAME: ColumnFamilyName =
    "transaction_accumulator";
pub const TRANSACTION_BY_ACCOUNT_CF_NAME: ColumnFamilyName =
    "transaction_by_account";
pub const TRANSACTION_INFO_CF_NAME: ColumnFamilyName = "transaction_info";
pub const LEDGER_INFO_BY_BLOCK_CF_NAME: ColumnFamilyName =
    "ledger_info_by_block";
pub const POS_STATE_CF_NAME: ColumnFamilyName = "pos_state";
pub const REWARD_EVENT_CF_NAME: ColumnFamilyName = "reward_event";
pub const COMMITTED_BLOCK_CF_NAME: ColumnFamilyName = "committed_block";
pub const COMMITTED_BLOCK_BY_VIEW_CF_NAME: ColumnFamilyName =
    "committed_block_by_view";
pub const LEDGER_INFO_BY_VOTED_BLOCK_CF_NAME: ColumnFamilyName =
    "ledger_info_by_voted_block";
pub const BLOCK_BY_EPOCH_AND_ROUND_CF_NAME: ColumnFamilyName =
    "block_by_epoch_and_round";

fn ensure_slice_len_eq(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() == len,
        "Unexpected data len {}, expected {}.",
        data.len(),
        len,
    );
    Ok(())
}

fn ensure_slice_len_gt(data: &[u8], len: usize) -> Result<()> {
    ensure!(
        data.len() > len,
        "Unexpected data len {}, expected to be greater than {}.",
        data.len(),
        len,
    );
    Ok(())
}

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use schemadb::schema::{KeyCodec, Schema, ValueCodec};

    macro_rules! decode_key_value {
        ($schema_type: ty, $data: ident) => {
            <<$schema_type as Schema>::Key as KeyCodec<$schema_type>>::decode_key($data);
            <<$schema_type as Schema>::Value as ValueCodec<$schema_type>>::decode_value($data);
        };
    }

    pub fn fuzz_decode(data: &[u8]) {
        #[allow(unused_must_use)]
        {
            decode_key_value!(
                super::epoch_by_version::EpochByVersionSchema,
                data
            );
            decode_key_value!(super::event::EventSchema, data);
            decode_key_value!(
                super::event_accumulator::EventAccumulatorSchema,
                data
            );
            decode_key_value!(super::event_by_key::EventByKeySchema, data);
            decode_key_value!(
                super::event_by_version::EventByVersionSchema,
                data
            );
            decode_key_value!(
                super::jellyfish_merkle_node::JellyfishMerkleNodeSchema,
                data
            );
            decode_key_value!(
                super::ledger_counters::LedgerCountersSchema,
                data
            );
            decode_key_value!(super::ledger_info::LedgerInfoSchema, data);
            decode_key_value!(
                super::stale_node_index::StaleNodeIndexSchema,
                data
            );
            decode_key_value!(super::transaction::TransactionSchema, data);
            decode_key_value!(
                super::transaction_accumulator::TransactionAccumulatorSchema,
                data
            );
            decode_key_value!(
                super::transaction_by_account::TransactionByAccountSchema,
                data
            );
            decode_key_value!(
                super::transaction_info::TransactionInfoSchema,
                data
            );
        }
    }
}
