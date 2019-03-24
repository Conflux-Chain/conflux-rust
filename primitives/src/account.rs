// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::hash::KECCAK_EMPTY;
use cfx_types::{Address, H256, U256};
use rlp::*;

pub struct Account {
    pub address: Address,
    pub balance: U256,
    pub nonce: U256,
    pub code_hash: H256,

    /// Not part of rlp.
    pub original_storage_root: H256,
}

impl Account {
    pub fn new_empty_with_balance(
        address: &Address, balance: &U256, nonce: &U256,
    ) -> Account {
        Self {
            address: address.clone(),
            balance: balance.clone(),
            nonce: nonce.clone(),
            original_storage_root: KECCAK_EMPTY,
            code_hash: KECCAK_EMPTY,
        }
    }

    pub fn set_original_storage_root(&mut self, storage_root: &H256) {
        self.original_storage_root = *storage_root;
    }

    pub fn new_from_rlp(
        address: &Address, rlp_bytes: &[u8], storage_root: &H256,
    ) -> Result<Account, DecoderError> {
        let mut account = rlp::decode::<Account>(rlp_bytes)?;
        account.set_original_storage_root(&storage_root);
        if !account.address.eq(address) {
            return Err(DecoderError::Custom("Address mismatch."));
        }

        Ok(account)
    }
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Account {
            address: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            nonce: rlp.val_at(2)?,
            original_storage_root: KECCAK_EMPTY,
            code_hash: rlp.val_at(3)?,
        })
    }
}

impl Encodable for Account {
    fn rlp_append(&self, stream: &mut RlpStream) {
        stream
            .begin_list(4)
            .append(&self.address)
            .append(&self.balance)
            .append(&self.nonce)
            .append(&self.code_hash);
    }
}
