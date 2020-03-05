// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{H160, H256, U256};
use primitives::Account as PrimitiveAccount;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub balance: U256,
    pub nonce: U256,
    pub code_hash: H256,
    pub bank_balance: U256,
    pub storage_balance: U256,
    pub bank_ar: U256,
    pub admin: H160,
}

impl Account {
    pub fn new(account: PrimitiveAccount) -> Self {
        Self {
            balance: account.balance.into(),
            nonce: account.nonce.into(),
            code_hash: account.code_hash.into(),
            bank_balance: account.bank_balance.into(),
            storage_balance: account.storage_balance.into(),
            bank_ar: account.bank_ar.into(),
            admin: account.admin.into(),
        }
    }
}
