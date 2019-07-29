// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{Context, Handleable, Message, MsgId},
    Error,
};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Debug, PartialEq)]
pub struct NewBlockHashes {
    pub block_hashes: Vec<H256>,
}

impl Handleable for NewBlockHashes {
    fn handle(self, ctx: &Context) -> Result<(), Error> {
        debug!("on_new_block_hashes, msg={:?}", self);

        if ctx.manager.catch_up_mode() {
            if let Ok(info) = ctx.manager.syn.get_peer_info(&ctx.peer) {
                let mut info = info.write();
                self.block_hashes.iter().for_each(|h| {
                    info.latest_block_hashes.insert(h.clone());
                });
            }
            return Ok(());
        }

        let headers_to_request = self
            .block_hashes
            .iter()
            .filter(|hash| !ctx.manager.graph.contains_block_header(&hash))
            .cloned()
            .collect::<Vec<_>>();

        // self.request_manager.request_block_headers(
        //     io,
        //     Some(peer),
        //     headers_to_request,
        // );

        ctx.manager.request_block_headers(
            ctx.io,
            Some(ctx.peer),
            headers_to_request,
        );

        Ok(())
    }
}

impl Message for NewBlockHashes {
    fn msg_id(&self) -> MsgId { MsgId::NEW_BLOCK_HASHES }

    fn msg_name(&self) -> &'static str { "NewBlockHashes" }
}

impl Encodable for NewBlockHashes {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream.append_list(&self.block_hashes);
    }
}

impl Decodable for NewBlockHashes {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(NewBlockHashes {
            block_hashes: rlp.as_list()?,
        })
    }
}
