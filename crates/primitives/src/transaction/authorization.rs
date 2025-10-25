use cfx_types::{Address, BigEndianHash, H256, U256};
use cfxkey::{public_to_address, Signature};
use keccak_hash::keccak;
use rlp::RlpStream;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

pub const AUTH_MAGIC: u8 = 0x05;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    RlpEncodable,
    RlpDecodable,
)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationListItem {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: u64,
    pub y_parity: u8,
    pub r: U256,
    pub s: U256,
}

pub type AuthorizationList = Vec<AuthorizationListItem>;

impl AuthorizationListItem {
    pub fn is_valid_y_parity(&self) -> bool {
        self.y_parity == 0 || self.y_parity == 1
    }

    pub fn is_chain_id_valid(&self, chain_id: u64) -> bool {
        self.chain_id == U256::from(chain_id) || self.chain_id.is_zero()
    }

    pub fn is_nonce_valid(&self) -> bool { self.nonce < u64::MAX }

    pub fn hash(&self) -> H256 {
        let mut rlp = RlpStream::new_list(3);
        rlp.append(&self.chain_id)
            .append(&self.address)
            .append(&self.nonce);

        let mut hash_input = vec![AUTH_MAGIC];
        hash_input.extend_from_slice(rlp.as_raw());

        keccak(hash_input)
    }

    pub fn signature(&self) -> Option<Signature> {
        let r: H256 = BigEndianHash::from_uint(&self.r);
        let s: H256 = BigEndianHash::from_uint(&self.s);
        let signature = Signature::from_rsv(&r, &s, self.y_parity);
        if !signature.is_low_s() || !signature.is_valid() {
            return None;
        }
        Some(signature)
    }

    pub fn authority(&self) -> Option<Address> {
        let signature = self.signature()?;
        let hash = self.hash();
        if let Ok(public) = cfxkey::recover(&signature, &hash) {
            Some(public_to_address(&public, false))
        } else {
            None
        }
    }
}
