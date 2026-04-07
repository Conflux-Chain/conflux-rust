// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! A map of subscribers.

use cfx_rpc_cfx_types::random;
pub use cfx_rpc_cfx_types::SubId as Id;
use cfx_rpc_utils::error::jsonrpsee_error_helpers::internal_error_with_data;
use cfx_types::H64;
use futures::StreamExt;
use jsonrpsee::{
    server::SubscriptionMessage, types::ErrorObject, SubscriptionSink,
};
use log::trace;
use serde::Serialize;
use std::{collections::HashMap, ops};
use tokio_stream::Stream;

pub struct Subscribers<T> {
    rand: random::Rng,
    subscriptions: HashMap<Id, T>,
}

impl<T> Default for Subscribers<T> {
    fn default() -> Self {
        Subscribers {
            rand: random::new(),
            subscriptions: HashMap::new(),
        }
    }
}

impl<T> Subscribers<T> {
    pub fn next_id(&mut self) -> Id {
        let data = H64::random_using(&mut self.rand);
        Id::new(data)
    }

    /// Insert new subscription and return assigned id.
    #[allow(dead_code)]
    pub fn insert(&mut self, val: T) -> Id {
        let id = self.next_id();
        self.subscriptions.insert(id.clone(), val);
        id
    }

    /// Removes subscription with given id and returns it (if any).
    pub fn remove(&mut self, id: &Id) -> Option<T> {
        trace!(target: "pubsub", "Removing subscription id={:?}", id);
        self.subscriptions.remove(&id)
    }
}

impl<T> ops::Deref for Subscribers<T> {
    type Target = HashMap<Id, T>;

    fn deref(&self) -> &Self::Target { &self.subscriptions }
}

/// Helper to convert a serde error into an [`ErrorObject`]
#[derive(Debug, thiserror::Error)]
#[error("Failed to serialize subscription item: {0}")]
pub struct SubscriptionSerializeError(#[from] serde_json::Error);

impl SubscriptionSerializeError {
    const fn new(err: serde_json::Error) -> Self { Self(err) }
}

impl From<SubscriptionSerializeError> for ErrorObject<'static> {
    fn from(value: SubscriptionSerializeError) -> Self {
        internal_error_with_data(value.to_string())
    }
}

/// Pipes all stream items to the subscription sink.
/// when the stream ends or the sink is closed, the function returns.
pub async fn pipe_from_stream<T, St>(
    sink: SubscriptionSink, mut stream: St,
) -> Result<(), ErrorObject<'static>>
where
    St: Stream<Item = T> + Unpin,
    T: Serialize,
{
    loop {
        tokio::select! {
            _ = sink.closed() => {
                // connection dropped: when user unsubscribes or network closed
                break Ok(())
            },
            maybe_item = stream.next() => {
                let item = match maybe_item {
                    Some(item) => item,
                    None => {
                        // stream ended
                        break  Ok(())
                    },
                };
                let msg = SubscriptionMessage::new(sink.method_name(), sink.subscription_id(), &item).map_err(SubscriptionSerializeError::new)?;
                if sink.send(msg).await.is_err() {
                    break Ok(());
                }
            }
        }
    }
}
