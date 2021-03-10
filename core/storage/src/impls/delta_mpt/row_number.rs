// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::errors::*;
// TODO: make it Delta MPT only. Add another type for Persistent MPT later.
pub type RowNumberUnderlyingType = u32;

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
    /// It's an error for row number to go higher than max u32 4_294_967_296. It
    /// shouldn't happen because for 2h lifetime it requires 596523 nodes /
    /// sec.
    pub const ROW_NUMBER_LIMIT: RowNumberUnderlyingType = 0xffffffff;

    pub fn get_next(&self) -> Result<RowNumber> {
        if self.value != Self::ROW_NUMBER_LIMIT {
            Ok(Self {
                value: self.value + 1,
            })
        } else {
            Err(ErrorKind::MPTTooManyNodes.into())
        }
    }
}

impl ToString for RowNumber {
    fn to_string(&self) -> String { self.value.to_string() }
}
