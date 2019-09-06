// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use futures::{Async, Future, Poll};
use std::{
    marker::PhantomData,
    ops::Add,
    time::{Duration, Instant},
};

use crate::light_protocol::{Error, ErrorKind};

pub struct Timeout<T> {
    t: Instant,
    msg: String,
    phantom: PhantomData<T>,
}

impl<T> Timeout<T> {
    pub fn after(dt: Duration, msg: String) -> Timeout<T> {
        Timeout {
            t: Instant::now().add(dt),
            msg,
            phantom: PhantomData,
        }
    }
}

impl<T> Future for Timeout<T> {
    type Error = Error;
    type Item = T;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match Instant::now() {
            t if t < self.t => Ok(Async::NotReady),
            _ => Err(ErrorKind::Msg(self.msg.clone()).into()),
        }
    }
}

/// Consume `future` and return a new one that raises and error with `msg` if
/// `future` is not ready before the given duration `d`.
pub fn with_timeout<Item>(
    d: Duration, msg: String, future: impl Future<Item = Item, Error = Error>,
) -> impl Future<Item = Item, Error = Error> {
    future
        .select(Timeout::<Item>::after(d, msg))
        .then(|x| match x {
            Ok((a, _)) => Ok(a),
            Err((a, _)) => Err(a),
        })
}
