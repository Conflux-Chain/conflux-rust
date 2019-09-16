// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use futures::{Async, Future, Stream};

use crate::{
    light_protocol::{Error, ErrorKind},
    parameters::light::POLL_PERIOD,
};

pub fn poll_future<T: Future>(future: &mut T) -> Result<T::Item, String>
where
    T::Item: std::fmt::Debug,
    T::Error: std::fmt::Debug,
{
    for ii in 0.. {
        trace!("poll number {}", ii);
        match future.poll() {
            Ok(Async::Ready(resp)) => {
                trace!("poll result: {:?}", resp);
                return Ok(resp);
            }
            Ok(Async::NotReady) => {
                trace!("poll result: NotReady");
            }
            Err(e) => {
                trace!("poll result: Error");
                return Err(format!("{:?}", e));
            }
        }

        trace!("sleeping...");
        std::thread::sleep(*POLL_PERIOD);
    }

    unreachable!()
}

pub fn poll_stream<T: Stream>(stream: &mut T) -> Result<Option<T::Item>, Error>
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
            }
            Err(e) => {
                trace!("poll result: Error");
                return Err(ErrorKind::Msg(format!("{:?}", e)).into());
            }
        }

        trace!("sleeping...");
        std::thread::sleep(*POLL_PERIOD);
    }

    unreachable!()
}
