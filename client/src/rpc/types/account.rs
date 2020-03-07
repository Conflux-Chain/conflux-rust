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
    pub staking_balance: U256,
    pub collateral_for_storage: U256,
    pub accumulated_interest_return: U256,
    pub admin: H160,
}

impl Account {
    pub fn new(account: PrimitiveAccount) -> Self {
        Self {
            balance: account.balance.into(),
            nonce: account.nonce.into(),
            code_hash: account.code_hash.into(),
            staking_balance: account.staking_balance.into(),
            collateral_for_storage: account.collateral_for_storage.into(),
            accumulated_interest_return: account
                .accumulated_interest_return
                .into(),
            admin: account.admin.into(),
        }
    }
}
