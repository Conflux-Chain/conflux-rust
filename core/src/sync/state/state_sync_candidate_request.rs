use crate::{
    message::{GetMaybeRequestId, Message, MsgId, RequestId, SetRequestId},
    sync::{
        message::{
            msgid, Context, DynamicCapability, Handleable, KeyContainer,
        },
        request_manager::{AsAny, Request},
        state::{
            state_sync_candidate_response::StateSyncCandidateResponse,
            storage::SnapshotSyncCandidate,
        },
        Error, ProtocolConfiguration,
    },
};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{any::Any, time::Duration};

#[derive(Clone, RlpEncodable, RlpDecodable, Debug)]
pub struct StateSyncCandidateRequest {
    pub request_id: RequestId,
    pub candidates: Vec<SnapshotSyncCandidate>,
}

build_msg_with_request_id_impl! { StateSyncCandidateRequest, msgid::STATE_SYNC_CANDIDATE_REQUEST, "StateSyncCandidateRequest" }

impl Handleable for StateSyncCandidateRequest {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let mut supported_candidates =
            Vec::with_capacity(self.candidates.len());
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
                                warn!(
                                    "Invalid SnapshotSyncCandidate, height unmatch: get {:?}, \
                                    local_height of the snapshot is {}",
                                    candidate, snapshot_info.height);
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

impl AsAny for StateSyncCandidateRequest {
    fn as_any(&self) -> &dyn Any { self }

    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}

impl Request for StateSyncCandidateRequest {
    fn timeout(&self, conf: &ProtocolConfiguration) -> Duration {
        conf.snapshot_candidate_request_timeout
    }

    fn on_removed(&self, _inflight_keys: &KeyContainer) {}

    fn with_inflight(&mut self, _inflight_keys: &KeyContainer) {}

    fn is_empty(&self) -> bool { false }

    fn resend(&self) -> Option<Box<dyn Request>> {
        Some(Box::new(self.clone()))
    }

    fn required_capability(&self) -> Option<DynamicCapability> { None }
}
