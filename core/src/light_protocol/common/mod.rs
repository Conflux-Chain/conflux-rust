// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod ledger_info;
mod peers;
mod unique_id;

pub use ledger_info::LedgerInfo;
pub use peers::{FullPeerFilter, FullPeerState, LightPeerState, Peers};
pub use unique_id::UniqueId;

use std::cmp;

pub fn max_of_collection<I, T: Ord>(collection: I) -> Option<T>
where I: Iterator<Item = T> {
    collection.fold(None, |max_so_far, x| match max_so_far {
        None => Some(x),
        Some(max_so_far) => Some(cmp::max(max_so_far, x)),
    })
}
