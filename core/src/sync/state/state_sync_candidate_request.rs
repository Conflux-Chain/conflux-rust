use crate::{
    message::RequestId,
    sync::{
        message::{Context, DynamicCapability, Handleable, KeyContainer},
        request_manager::Request,
        state::{
            state_sync_candidate_response::StateSyncCandidateResponse,
            storage::SnapshotSyncCandidate,
        },
        Error, ErrorKind, ProtocolConfiguration,
    },
};
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::time::Duration;

#[derive(Clone, RlpEncodable, RlpDecodable, Debug)]
pub struct StateSyncCandidateRequest {
    pub request_id: RequestId,
    pub candidates: Vec<SnapshotSyncCandidate>,
}

impl Handleable for StateSyncCandidateRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let mut supported_candidates = Vec::new();
        let storage_manager = ctx
            .manager
            .graph
            .data_man
            .storage_manager
            .get_storage_manager();
        for candidate in self.candidates {
            match candidate {
                SnapshotSyncCandidate::FullSync {
                    height,
                    snapshot_epoch_id,
                } => {
                    match storage_manager
                        .get_snapshot_info_at_epoch(&snapshot_epoch_id)
                    {
                        Some(snapshot_info) => {
                            if snapshot_info.height == height {
                                supported_candidates.push(
                                    SnapshotSyncCandidate::FullSync {
                                        height,
                                        snapshot_epoch_id,
                                    },
                                );
                            } else {
                                warn!("Invalid SnapshotSyncCandidate, height unmatch: get {:?}, local_height of the snapshot is {}", candidate, snapshot_info.height);
                                bail!(ErrorKind::UnexpectedMessage(
                                    "Invalid snapshot sync candidate".into(),
                                ));
                            }
                        }
                        None => {
                            debug!(
                                "Requested snapshot not exist: {:?}",
                                candidate
                            );
                        }
                    }
                }
                _ => {
                    warn!("Unsupported candidate: {:?}", candidate);
                    bail!(ErrorKind::UnexpectedMessage("candidate in StateSyncCandidateRequest is not supported".into()));
                }
            }
        }
        ctx.send_response(&StateSyncCandidateResponse {
            request_id: self.request_id,
            supported_candidates,
        })?;

        Ok(())
    }
}

impl Request for StateSyncCandidateRequest {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.snapshot_candidate_request_timeout_ms
    }

    fn on_removed(&self, _inflight_keys: &KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> { None }

    fn required_capability(&self) -> Option<DynamicCapability> { None }
}
