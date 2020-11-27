// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod ledger_info;
mod peers;

pub use ledger_info::LedgerInfo;
pub use peers::{FullPeerFilter, FullPeerState, LightPeerState, Peers};

use super::{Error, ErrorKind};
use cfx_internal_common::ChainIdParamsInner;
use std::{cmp, fmt::Debug};

pub fn max_of_collection<I, T: Ord>(collection: I) -> Option<T>
where I: Iterator<Item = T> {
    collection.fold(None, |max_so_far, x| match max_so_far {
        None => Some(x),
        Some(max_so_far) => Some(cmp::max(max_so_far, x)),
    })
}

pub fn validate_chain_id(
    ours: &ChainIdParamsInner, theirs: ChainIdParamsInner, peer_height: u64,
) -> Result<(), Error> {
    if !ours.matches(&theirs, peer_height) {
        let error_kind = ErrorKind::ChainIdMismatch {
            ours: ours.clone(),
            theirs,
        };
        debug!("{:?}", error_kind);
        bail!(error_kind);
    } else {
        Ok(())
    }
}

// TODO(thegaram): consider distinguishing between expected and unexpected
// errors, e.g. some errors suggest the peer requested a non-existent item
// (normal) while others suggest a local db inconsistency (exception).
pub fn partition_results<I, E>(
    it: impl Iterator<Item = Result<I, E>>,
) -> (Vec<I>, Vec<E>)
where
    I: Debug,
    E: Debug,
{
    let (success, failure): (Vec<_>, Vec<_>) = it.partition(Result::is_ok);
    let success = success.into_iter().map(Result::unwrap).collect();
    let failure = failure.into_iter().map(Result::unwrap_err).collect();
    (success, failure)
}
