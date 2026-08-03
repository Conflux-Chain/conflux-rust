// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::errors::*;
// TODO: make it Delta MPT only. Add another type for Persistent MPT later.
#[cfg(not(feature = "u64_mpt_db_key"))]
pub type RowNumberUnderlyingType = u32;
#[cfg(feature = "u64_mpt_db_key")]
pub type RowNumberUnderlyingType = u64;
/// Because the Merkle Hash is too large to store for links to children in MPT,
/// and it's only useful for persistence, in delta MPT we use row number as
/// storage key.
///
/// Using RowNumber as node index is also more space/time efficient than other
/// Maps in standard library, given that our goal of
#[derive(Copy, Clone, Default)]
pub struct RowNumber {
    pub value: RowNumberUnderlyingType,
}

impl RowNumber {
    /// Cap at `2^(BITS-1) - 1` (2^31-1 for u32, 2^63-1 for u64): the compact
    /// node ref (`node_ref.rs`) reserves the top bit of a committed db_key for
    /// its persistent-key encoding, so a db_key must keep its MSB clear, and
    /// this is the largest value that does.
    pub const ROW_NUMBER_LIMIT: RowNumberUnderlyingType =
        (1 << (RowNumberUnderlyingType::BITS - 1)) - 1;

    pub fn get_next(&self) -> Result<RowNumber> {
        if self.value != Self::ROW_NUMBER_LIMIT {
            Ok(Self {
                value: self.value + 1,
            })
        } else {
            Err(Error::MPTTooManyNodes.into())
        }
    }
}

impl ToString for RowNumber {
    fn to_string(&self) -> String { self.value.to_string() }
}
