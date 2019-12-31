use crate::{
    message::RequestId,
    sync::{
        message::{Context, Handleable},
        state::{storage::SnapshotSyncCandidate, StateSyncCandidateRequest},
        Error, ErrorKind,
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
        if let Some(candidate) =
            ctx.manager.state_sync.handle_snapshot_candidate_response(
                &ctx.peer,
                &self.supported_candidates,
                &request.candidates,
            )
        {
            // Start retrieving state of candidate
            let epoch_to_sync = match candidate {
                SnapshotSyncCandidate::FullSync {
                    height: _,
                    snapshot_epoch_id,
                } => snapshot_epoch_id,
                _ => {
                    warn!("Unsupported candidate: {:?}", candidate);
                    bail!(ErrorKind::UnexpectedMessage("candidate in StateSyncCandidateRequest is not supported".into()));
                }
            };
            match ctx
                .manager
                .graph
                .consensus
                .get_trusted_blame_block(&epoch_to_sync)
            {
                Some(trusted_blame_block) => {
                    info!("start to sync state for checkpoint {:?}, trusted blame block = {:?}", epoch_to_sync, trusted_blame_block);
                    ctx.manager.state_sync.start_state_sync(
                        epoch_to_sync,
                        trusted_blame_block,
                        ctx.io,
                        ctx.manager,
                    );
                }
                None => {
                    // FIXME should find the trusted blame block
                    error!("failed to start checkpoint sync, the trusted blame block is unavailable, epoch_to_sync={:?}", epoch_to_sync);
                    bail!(ErrorKind::UnexpectedMessage(
                        "Not trust blame block for epoch_to_sync".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}
