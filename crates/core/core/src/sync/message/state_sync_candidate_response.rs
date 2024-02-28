use crate::{
    message::{
        GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId,
        RequestId,
    },
    sync::{
        message::{msgid, Context, Handleable, StateSyncCandidateRequest},
        state::storage::SnapshotSyncCandidate,
        Error, SYNC_PROTO_V1, SYNC_PROTO_V3,
    },
};
use network::service::ProtocolVersion;
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(RlpEncodable, RlpDecodable, Debug)]
pub struct StateSyncCandidateResponse {
    pub request_id: RequestId,
    pub supported_candidates: Vec<SnapshotSyncCandidate>,
}

build_msg_impl! {
    StateSyncCandidateResponse, msgid::STATE_SYNC_CANDIDATE_RESPONSE,
    "StateSyncCandidateResponse", SYNC_PROTO_V1, SYNC_PROTO_V3
}

impl Handleable for StateSyncCandidateResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;
        let request = message.downcast_ref::<StateSyncCandidateRequest>(
            ctx.io,
            &ctx.manager.request_manager,
        )?;
        debug!("Receive StateSyncCandidateResponse={:?}", self);
        ctx.manager.state_sync.handle_snapshot_candidate_response(
            &ctx.node_id,
            &self.supported_candidates,
            &request.candidates,
        );
        Ok(())
    }
}
