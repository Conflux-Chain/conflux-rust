// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, RequestId},
    parameters::sync::MAX_EPOCHS_TO_SEND,
    sync::{
        message::{
            Context, GetBlockHashesResponse, Handleable, Key, KeyContainer,
        },
        request_manager::{AsAny, Request},
        Error, ProtocolConfiguration,
    },
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(
    Debug, PartialEq, Clone, RlpDecodable, RlpEncodable, DeriveMallocSizeOf,
)]
pub struct GetBlockHashesByEpoch {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

impl AsAny for GetBlockHashesByEpoch {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for GetBlockHashesByEpoch {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());
        for epoch in self.epochs.iter() {
            inflight_keys.remove(&Key::Num(*epoch));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &KeyContainer) {
        let mut inflight_keys = inflight_keys.write(self.msg_id());
        self.epochs
            .retain(|epoch| inflight_keys.insert(Key::Num(*epoch)));
    }

    fn is_empty(&self) -> bool { self.epochs.is_empty() }

    fn resend(&self) -> Option<Box<dyn Request>> {
        Some(Box::new(self.clone()))
    }
}

impl Handleable for GetBlockHashesByEpoch {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let hashes = self
            .epochs
            .iter()
            .take(MAX_EPOCHS_TO_SEND as usize)
            .map(|&e| ctx.manager.graph.get_all_block_hashes_by_epoch(e))
            .filter_map(Result::ok)
            .fold(vec![], |mut res, sub| {
                res.extend(sub);
                res
            });

        let response = GetBlockHashesResponse {
            request_id: self.request_id,
            hashes,
        };

        ctx.send_response(&response)
    }
}
