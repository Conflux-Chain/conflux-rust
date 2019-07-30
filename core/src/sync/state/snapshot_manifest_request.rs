// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{HasRequestId, Message, MsgId, RequestId},
    sync::{
        message::{msgid, Context, Handleable, KeyContainer},
        request_manager::Request,
        state::snapshot_manifest_response::SnapshotManifestResponse,
        Error, ProtocolConfiguration,
    },
};
use cfx_types::H256;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Debug, Clone, RlpDecodable, RlpEncodable)]
pub struct SnapshotManifestRequest {
    pub request_id: u64,
    pub checkpoint: H256,
}

impl SnapshotManifestRequest {
    pub fn new(checkpoint: H256) -> Self {
        SnapshotManifestRequest {
            request_id: 0,
            checkpoint,
        }
    }
}

build_msg_impl! { SnapshotManifestRequest, msgid::GET_SNAPSHOT_MANIFEST, "SnapshotManifestRequest" }
build_has_request_id_impl! { SnapshotManifestRequest }

impl Handleable for SnapshotManifestRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        // todo find manifest from storage APIs
        let response = SnapshotManifestResponse {
            request_id: self.request_id,
            checkpoint: self.checkpoint.clone(),
            chunk_hashes: Vec::new(),
        };

        ctx.send_response(&response)
    }
}

impl Request for SnapshotManifestRequest {
    fn as_message(&self) -> &Message { self }

    fn as_any(&self) -> &Any { self }

    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.headers_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &mut KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &mut KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<Request>> { Some(Box::new(self.clone())) }
}
