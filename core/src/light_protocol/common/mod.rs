// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod ledger_info;
mod ledger_proof;
mod peers;
mod timeout;
mod unique_id;
mod validate;

pub use ledger_info::LedgerInfo;
pub use ledger_proof::LedgerProof;
pub use peers::Peers;
pub use timeout::{with_timeout, Timeout};
pub use unique_id::UniqueId;
pub use validate::Validate;

extern crate futures;
use crate::parameters::light::POLL_PERIOD_MS;
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
    for ii in 0.. {
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

    unreachable!()
}
