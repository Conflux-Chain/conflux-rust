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
use cfx_types::H64;
use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    SubscriptionId,
};
use log::{debug, trace};
use std::{collections::HashMap, ops};

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
    pub fn insert(&mut self, val: T) -> SubscriptionId {
        let id = self.next_id();
        debug!(target: "pubsub", "Adding subscription id={:?}", id);
        let s = id.as_string();
        self.subscriptions.insert(id, val);
        SubscriptionId::String(s)
    }

    /// Removes subscription with given id and returns it (if any).
    pub fn remove(&mut self, id: &SubscriptionId) -> Option<T> {
        trace!(target: "pubsub", "Removing subscription id={:?}", id);
        match *id {
            SubscriptionId::String(ref id) => match id.parse() {
                Ok(id) => self.subscriptions.remove(&id),
                Err(_) => None,
            },
            _ => None,
        }
    }
}

impl<T> Subscribers<Sink<T>> {
    /// Assigns id and adds a subscriber to the list.
    pub fn push(&mut self, sub: Subscriber<T>) -> Id {
        let id = self.next_id();
        if let Ok(sink) = sub.assign_id(SubscriptionId::String(id.as_string()))
        {
            debug!(target: "pubsub", "Adding subscription id={:?}", id);
            self.subscriptions.insert(id.clone(), sink);
        }

        id
    }
}

impl<T, V> Subscribers<(Sink<T>, V)> {
    /// Assigns id and adds a subscriber to the list.
    pub fn push(&mut self, sub: Subscriber<T>, val: V) -> Id {
        let id = self.next_id();
        if let Ok(sink) = sub.assign_id(SubscriptionId::String(id.as_string()))
        {
            debug!(target: "pubsub", "Adding subscription id={:?}", id);
            self.subscriptions.insert(id.clone(), (sink, val));
        }

        id
    }
}

impl<T> ops::Deref for Subscribers<T> {
    type Target = HashMap<Id, T>;

    fn deref(&self) -> &Self::Target { &self.subscriptions }
}
