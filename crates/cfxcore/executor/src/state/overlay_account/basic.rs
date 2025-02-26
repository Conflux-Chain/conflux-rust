use cfx_bytes::Bytes;
use cfx_types::{Address, AddressWithSpace, H256, U256};
use cfx_vm_types::CODE_PREFIX_7702;
use keccak_hash::{keccak, KECCAK_EMPTY};
use primitives::{storage::STORAGE_LAYOUT_REGULAR_V0, CodeInfo};
use std::sync::Arc;

use super::OverlayAccount;

impl OverlayAccount {
    pub fn address(&self) -> &AddressWithSpace { &self.address }

    pub fn nonce(&self) -> &U256 { &self.nonce }

    pub fn set_nonce(&mut self, nonce: &U256) { self.nonce = *nonce; }

    pub fn inc_nonce(&mut self) { self.nonce = self.nonce + U256::from(1u8); }

    pub fn balance(&self) -> &U256 { &self.balance }

    pub fn add_balance(&mut self, by: &U256) {
        self.balance = self.balance + *by;
    }

    pub fn sub_balance(&mut self, by: &U256) {
        assert!(self.balance >= *by);
        self.balance = self.balance - *by;
    }

    pub fn admin(&self) -> &Address {
        self.address.assert_native();
        &self.admin
    }

    pub fn set_admin(&mut self, admin: &Address) {
        self.address.assert_native();
        self.admin = admin.clone();
    }

    pub fn init_code(
        &mut self, code: Bytes, owner: Address, transaction_hash: H256,
    ) {
        self.code_hash = keccak(&code);
        self.code = Some(CodeInfo {
            code: Arc::new(code),
            owner,
        });
        self.create_transaction_hash = Some(transaction_hash);
    }

    pub fn override_code(&mut self, code: Bytes, owner: Address) {
        self.code_hash = keccak(&code);
        self.code = Some(CodeInfo {
            code: Arc::new(code),
            owner,
        });
    }

    pub fn set_authorization(&mut self, address: &Address) {
        self.address.assert_ethereum();

        self.inc_nonce();

        if !address.is_zero() {
            let mut code = CODE_PREFIX_7702.to_vec();
            code.extend_from_slice(&address[..]);
            self.code_hash = keccak(&code);
            self.code = Some(CodeInfo {
                code: Arc::new(code),
                owner: Address::zero(),
            });
            self.storage_layout_change = Some(STORAGE_LAYOUT_REGULAR_V0);
        } else {
            self.code_hash = KECCAK_EMPTY;
            self.code = None;
        }
    }

    pub(super) fn is_code_loaded(&self) -> bool {
        self.code.is_some() || self.code_hash == KECCAK_EMPTY
    }

    pub fn code_hash(&self) -> H256 { self.code_hash.clone() }

    pub fn create_transaction_hash(&self) -> Option<H256> {
        self.create_transaction_hash
    }

    pub fn is_null(&self) -> bool {
        self.balance.is_zero()
            && self.staking_balance.is_zero()
            && self.collateral_for_storage.is_zero()
            && self.nonce.is_zero()
            && self.code_hash == KECCAK_EMPTY
    }
}
