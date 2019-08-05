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
        request_manager::Request,
        Error, ProtocolConfiguration,
    },
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, PartialEq, Clone, RlpDecodable, RlpEncodable)]
pub struct GetBlockHashesByEpoch {
    pub request_id: RequestId,
    pub epochs: Vec<u64>,
}

impl Request for GetBlockHashesByEpoch {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        for epoch in self.epochs.iter() {
            inflight_keys.remove(msg_type, Key::Num(*epoch));
        }
    }

    fn with_inflight(&mut self, inflight_keys: &mut KeyContainer) {
        let msg_type = self.msg_id().into();
        self.epochs
            .retain(|epoch| inflight_keys.add(msg_type, Key::Num(*epoch)));
    }

    fn is_empty(&self) -> bool { self.epochs.is_empty() }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}

impl Handleable for GetBlockHashesByEpoch {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let hashes = self
            .epochs
            .iter()
            .take(MAX_EPOCHS_TO_SEND as usize)
            .map(|&e| ctx.manager.graph.get_block_hashes_by_epoch(e))
            .filter_map(Result::ok)
            .fold(vec![], |mut res, sub| {
                res.extend(sub);
                res
            });

        let response = GetBlockHashesResponse {
            request_id: self.request_id.clone(),
            hashes,
        };

        ctx.send_response(&response)
    }
}
