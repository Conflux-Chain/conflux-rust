// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod error;
mod synchronization_graph;
mod synchronization_protocol_handler;
mod synchronization_service;
mod synchronization_state;

pub use self::{
    error::{Error, ErrorKind},
    synchronization_graph::{
        BestInformation, SharedSynchronizationGraph, SyncGraphStatistics,
        SynchronizationGraph, SynchronizationGraphInner,
        SynchronizationGraphNode,
    },
    synchronization_protocol_handler::{
        ProtocolConfiguration, SynchronizationProtocolHandler,
        SYNCHRONIZATION_PROTOCOL_VERSION,
    },
    synchronization_service::{
        SharedSynchronizationService, SynchronizationService,
    },
    synchronization_state::{SynchronizationPeerState, SynchronizationState},
};

pub mod random {
    use rand;
    pub fn new() -> rand::ThreadRng { rand::thread_rng() }
}
