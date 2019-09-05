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

///! Cfx PUB-SUB rpc interface.
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;
use jsonrpc_pubsub::{typed, SubscriptionId};

use crate::rpc::types::pubsub;

/// Cfx PUB-SUB rpc interface.
#[rpc(server)]
pub trait PubSub {
    type Metadata;

    /// Subscribes to Cfx subscription.
    #[pubsub(
        subscription = "cfx_subscription",
        subscribe,
        name = "cfx_subscribe"
    )]
    fn subscribe(
        &self, _: Self::Metadata, _: typed::Subscriber<pubsub::Result>,
        _: pubsub::Kind, _: Option<pubsub::Params>,
    );

    /// Unsubscribe from existing Cfx subscription.
    #[pubsub(
        subscription = "cfx_subscription",
        unsubscribe,
        name = "cfx_unsubscribe"
    )]
    fn unsubscribe(
        &self, _: Option<Self::Metadata>, _: SubscriptionId,
    ) -> Result<bool>;
}
