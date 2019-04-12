// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{Message, MsgId};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[allow(dead_code)]
pub const MAINNET_ID: u8 = 0x0;
#[allow(dead_code)]
pub const TESTNET_ID: u8 = 0x1;

#[derive(Debug, PartialEq)]
pub struct Status {
    pub protocol_version: u8,
    pub network_id: u8,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub terminal_block_hashes: Vec<H256>,
}

impl Message for Status {
    fn msg_id(&self) -> MsgId { MsgId::STATUS }
}

impl Encodable for Status {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(5)
            .append(&self.protocol_version)
            .append(&self.network_id)
            .append(&self.genesis_hash)
            .append(&self.best_epoch)
            .append_list(&self.terminal_block_hashes);
    }
}

impl Decodable for Status {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Status {
            protocol_version: rlp.val_at::<u8>(0)?,
            network_id: rlp.val_at::<u8>(1)?,
            genesis_hash: rlp.val_at::<H256>(2)?,
            best_epoch: rlp.val_at::<u64>(3)?,
            terminal_block_hashes: rlp.list_at(4)?,
        })
    }
}
