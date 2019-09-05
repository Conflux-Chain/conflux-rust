// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum NodeType {
    Full,
    Light,
    Unknown,
}

impl Default for NodeType {
    fn default() -> NodeType { NodeType::Unknown }
}

impl From<u8> for NodeType {
    fn from(raw: u8) -> NodeType {
        match raw {
            0 => NodeType::Full,
            1 => NodeType::Light,
            _ => NodeType::Unknown,
        }
    }
}

impl From<&NodeType> for u8 {
    fn from(node_type: &NodeType) -> u8 {
        match node_type {
            NodeType::Full => 0,
            NodeType::Light => 1,
            NodeType::Unknown => 0xff,
        }
    }
}

impl Encodable for NodeType {
    fn rlp_append(&self, s: &mut RlpStream) {
        let raw: u8 = self.into();
        s.append_internal(&raw);
    }
}

impl Decodable for NodeType {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let raw: u8 = rlp.as_val()?;
        Ok(NodeType::from(raw))
    }
}
