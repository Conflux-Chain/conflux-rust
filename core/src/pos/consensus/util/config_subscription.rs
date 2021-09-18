// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use channel::diem_channel::Receiver;
use diem_types::on_chain_config::{
    new_epoch_event_key, OnChainConfigPayload, ON_CHAIN_CONFIG_REGISTRY,
};
use subscription_service::ReconfigSubscription;

/// Creates consensus's subscription to reconfiguration notification from state
/// sync
pub fn gen_consensus_reconfig_subscription(
) -> (ReconfigSubscription, Receiver<(), OnChainConfigPayload>) {
    ReconfigSubscription::subscribe_all(
        "consensus",
        ON_CHAIN_CONFIG_REGISTRY.to_vec(),
        vec![new_epoch_event_key()],
    )
}
