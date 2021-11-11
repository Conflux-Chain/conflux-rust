// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use diem_types::block_info::PivotBlockDecision;
use serde_derive::Serialize;

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub block_hash: H256,
    pub height: U64,
}

impl From<&PivotBlockDecision> for Decision {
    fn from(pd: &PivotBlockDecision) -> Self {
        Decision {
            block_hash: pd.block_hash,
            height: U64::from(pd.height),
        }
    }
}
