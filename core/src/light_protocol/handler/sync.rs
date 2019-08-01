// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp::Rlp;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::{
    light_protocol::Error,
    message::RequestId,
    network::{NetworkContext, PeerId},
};

pub struct SyncHandler {
    next_request_id: Arc<AtomicU64>,
}

impl SyncHandler {
    pub fn new(next_request_id: Arc<AtomicU64>) -> Self {
        SyncHandler { next_request_id }
    }

    #[allow(dead_code)]
    pub(super) fn on_block_headers(
        &self, _io: &NetworkContext, _peer: PeerId, _rlp: &Rlp,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn next_request_id(&self) -> RequestId {
        self.next_request_id.fetch_add(1, Ordering::Relaxed).into()
    }
}
