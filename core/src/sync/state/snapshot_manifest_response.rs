// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockExecutionResult,
    message::{GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId},
    sync::{
        message::{msgid, Context, Handleable},
        state::{storage::RangedManifest, SnapshotManifestRequest},
        Error, ErrorKind, SYNC_PROTO_V1, SYNC_PROTO_V2,
    },
};
use cfx_types::H256;
use network::service::ProtocolVersion;
use primitives::{MerkleHash, StateRoot};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(RlpDecodable, RlpEncodable, Default)]
pub struct SnapshotManifestResponse {
    pub request_id: u64,
    pub manifest: RangedManifest,
    // FIXME: this TODO must be addressed before release, or we must have a
    // FIXME: protocol version field
    //
    // We actually need state_root_blame_vec for two epochs: snapshot_epoch_id
    // and its next snapshot + 1 epoch; and the state_root of snapshot_epoch_id
    // and the state root of its next snapshot + 1 epoch to get
    // snapshot_merkle_root of snapshot_epoch_id. The
    // current implementation passes state_blame_vec for the entire range of
    // snapshot_epoch_id to its next snapshot's trusted blame block,
    // which should be improved.
    //
    // TODO: reduce the data to pass over network.
    pub state_root_vec: Vec<StateRoot>,
    pub receipt_blame_vec: Vec<H256>,
    pub bloom_blame_vec: Vec<H256>,
    pub block_receipts: Vec<BlockExecutionResult>,

    // Debug only field.
    // TODO: can be deleted later.
    pub snapshot_merkle_root: MerkleHash,
}

build_msg_impl! {
    SnapshotManifestResponse, msgid::GET_SNAPSHOT_MANIFEST_RESPONSE,
    "SnapshotManifestResponse", SYNC_PROTO_V1, SYNC_PROTO_V2
}

impl Handleable for SnapshotManifestResponse {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        let message = ctx.match_request(self.request_id)?;

        let request = message.downcast_ref::<SnapshotManifestRequest>(
            ctx.io,
            &ctx.manager.request_manager,
        )?;

        if let Err(e) = self.validate(ctx, request) {
            ctx.manager
                .request_manager
                .resend_request_to_another_peer(ctx.io, &message);
            return Err(e);
        }

        ctx.manager
            .state_sync
            .handle_snapshot_manifest_response(ctx, self, &request)?;

        Ok(())
    }
}

impl SnapshotManifestResponse {
    fn validate(
        &self, _: &Context, request: &SnapshotManifestRequest,
    ) -> Result<(), Error> {
        if request.is_initial_request() && self.state_root_vec.is_empty() {
            debug!("Responded snapshot manifest has empty blame states");
            bail!(ErrorKind::InvalidSnapshotManifest(
                "state blame vector not found".into()
            ));
        }

        if self.state_root_vec.len() != self.receipt_blame_vec.len()
            || self.state_root_vec.len() != self.bloom_blame_vec.len()
        {
            debug!("Responded snapshot manifest has mismatch blame states/receipts/blooms");
            bail!(ErrorKind::InvalidSnapshotManifest(
                "blame vector length mismatch".into()
            ));
        }

        Ok(())
    }
}
