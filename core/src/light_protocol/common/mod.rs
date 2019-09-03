// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod ledger_info;
mod ledger_proof;
mod peers;
mod unique_id;
mod validate;

pub use ledger_info::LedgerInfo;
pub use ledger_proof::LedgerProof;
pub use peers::Peers;
pub use unique_id::UniqueId;
pub use validate::Validate;

extern crate futures;
use crate::parameters::light::{MAX_POLL_TIME_MS, POLL_PERIOD_MS};
use futures::{Async, Stream};
use std::cmp;

use crate::light_protocol::{Error, ErrorKind};

pub fn max_of_collection<I, T: Ord>(collection: I) -> Option<T>
where I: Iterator<Item = T> {
    collection.fold(None, |max_so_far, x| match max_so_far {
        None => Some(x),
        Some(max_so_far) => Some(cmp::max(max_so_far, x)),
    })
}

pub fn poll_next<T: Stream>(stream: &mut T) -> Result<Option<T::Item>, Error>
where
    T::Item: std::fmt::Debug,
    T::Error: std::fmt::Debug,
{
    // poll stream result
    // TODO(thegaram): come up with something better
    // we can consider returning the stream/future directly
    let max_poll_num = MAX_POLL_TIME_MS / POLL_PERIOD_MS;

    for ii in 0..max_poll_num {
        trace!("poll number {}", ii);
        match stream.poll() {
            Ok(Async::Ready(resp)) => {
                trace!("poll result: {:?}", resp);
                return Ok(resp);
            }
            Ok(Async::NotReady) => {
                trace!("poll result: NotReady");
                ()
            }
            Err(e) => {
                trace!("poll result: Error");
                return Err(ErrorKind::Msg(format!("{:?}", e)).into());
            }
        }

        trace!("sleeping...");
        let d = std::time::Duration::from_millis(POLL_PERIOD_MS);
        std::thread::sleep(d);
    }

    trace!("poll timeout");
    Err(ErrorKind::NoResponse.into())
}
