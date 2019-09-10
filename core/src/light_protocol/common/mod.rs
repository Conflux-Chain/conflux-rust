// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod ledger_info;
mod ledger_proof;
mod peers;
mod poll;
mod timeout;
mod unique_id;
mod validate;

pub use ledger_info::LedgerInfo;
pub use ledger_proof::LedgerProof;
pub use peers::Peers;
pub use poll::{poll_future, poll_stream};
pub use timeout::{with_timeout, Timeout};
pub use unique_id::UniqueId;
pub use validate::Validate;

use std::cmp;

pub fn max_of_collection<I, T: Ord>(collection: I) -> Option<T>
where I: Iterator<Item = T> {
    collection.fold(None, |max_so_far, x| match max_so_far {
        None => Some(x),
        Some(max_so_far) => Some(cmp::max(max_so_far, x)),
    })
}
