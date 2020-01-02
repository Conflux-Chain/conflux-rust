use crate::{
    message::RequestId,
    sync::{
        message::{Context, Handleable},
        state::{storage::SnapshotSyncCandidate, StateSyncCandidateRequest},
        Error,
    },
};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(RlpEncodable, RlpDecodable)]
pub struct StateSyncCandidateResponse {
    pub request_id: RequestId,
    pub supported_candidates: Vec<SnapshotSyncCandidate>,
}

impl Handleable for StateSyncCandidateResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;
        let request = message.downcast_ref::<StateSyncCandidateRequest>(
            ctx.io,
            &ctx.manager.request_manager,
            true,
        )?;
        ctx.manager.state_sync.handle_snapshot_candidate_response(
            &ctx.peer,
            &self.supported_candidates,
            &request.candidates,
        );
        Ok(())
    }
}
