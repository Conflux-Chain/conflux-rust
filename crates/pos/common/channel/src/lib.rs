// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

//! Provides an mpsc (multi-producer single-consumer) channel. While there is
//! only one `channel::Receiver`, there can be many `channel::Sender`s, which
//! are also cheap to clone.
//!
//! This channel differs from our other channel implementation,
//! `channel::diem_channel`, in that it is just a single queue (vs. different
//! queues for different keys) with backpressure (senders will block if the
//! queue is full instead of evicting another item in the queue) that only
//! implements FIFO (vs. LIFO or KLAST).

use futures::{
    channel::mpsc,
    sink::Sink,
    stream::{FusedStream, Stream},
    task::{Context, Poll},
};
use std::pin::Pin;

#[cfg(test)]
mod test;

pub mod diem_channel;
#[cfg(test)]
mod diem_channel_test;

pub mod message_queues;
#[cfg(test)]
mod message_queues_test;

pub struct Sender<T> {
    inner: mpsc::Sender<T>,
}

pub struct Receiver<T> {
    inner: mpsc::Receiver<T>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Sink<T> for Sender<T> {
    type Error = mpsc::SendError;

    fn poll_ready(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        (*self).inner.poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, msg: T) -> Result<(), Self::Error> {
        (*self).inner.start_send(msg)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

impl<T> Sender<T> {
    pub fn try_send(&mut self, msg: T) -> Result<(), mpsc::SendError> {
        (*self)
            .inner
            .try_send(msg)
            .map_err(mpsc::TrySendError::into_send_error)
    }
}

impl<T> FusedStream for Receiver<T>
where T: std::fmt::Debug
{
    fn is_terminated(&self) -> bool { self.inner.is_terminated() }
}

impl<T> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>, cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

pub fn new<T>(size: usize) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = mpsc::channel(size);
    (Sender { inner: sender }, Receiver { inner: receiver })
}
