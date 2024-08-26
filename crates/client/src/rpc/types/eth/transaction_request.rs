// Copyright 2019-2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

use crate::rpc::types::{Bytes, MAX_GAS_CALL_REQUEST};
use cfx_types::{Address, AddressSpaceUtil, H160, U256, U64};
use primitives::{
    transaction::{
        Action, Eip1559Transaction, Eip155Transaction, Eip2930Transaction,
        EthereumTransaction::*, SignedTransaction, EIP1559_TYPE, EIP2930_TYPE,
        LEGACY_TX_TYPE,
    },
    AccessList,
};
use std::cmp::min;

/// Call request
#[derive(Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionRequest {
    /// From
    pub from: Option<H160>,
    /// To
    pub to: Option<H160>,
    /// Gas Price
    pub gas_price: Option<U256>,
    /// Max fee per gas
    pub max_fee_per_gas: Option<U256>,
    /// Gas
    pub gas: Option<U256>,
    /// Value
    pub value: Option<U256>,
    /// Data
    pub data: Option<Bytes>,
    /// Nonce
    pub nonce: Option<U256>,
    /// Miner bribe
    pub max_priority_fee_per_gas: Option<U256>,
    pub access_list: Option<AccessList>,
    #[serde(rename = "type")]
    pub transaction_type: Option<U64>,
}

impl TransactionRequest {
    pub fn unset_zero_gas_price(&mut self) {
        if self.gas_price == Some(U256::zero()) {
            self.gas_price = None;
        }
    }

    pub fn sign_call(self, chain_id: u32) -> Result<SignedTransaction, String> {
        let request = self;
        let max_gas = U256::from(MAX_GAS_CALL_REQUEST);
        let gas = min(request.gas.unwrap_or(max_gas), max_gas);
        let nonce = request.nonce.unwrap_or_default();
        let action =
            request.to.map_or(Action::Create, |addr| Action::Call(addr));
        let value = request.value.unwrap_or_default();

        let default_type_id = if request.max_fee_per_gas.is_some()
            || request.max_priority_fee_per_gas.is_some()
        {
            EIP1559_TYPE
        } else if request.access_list.is_some() {
            EIP2930_TYPE
        } else {
            LEGACY_TX_TYPE
        };
        let transaction_type = request
            .transaction_type
            .unwrap_or(U64::from(default_type_id));

        let gas_price = request.gas_price.unwrap_or(1.into());
        let max_fee_per_gas = request
            .max_fee_per_gas
            .or(request.max_priority_fee_per_gas)
            .unwrap_or(gas_price);
        let max_priority_fee_per_gas =
            request.max_priority_fee_per_gas.unwrap_or(U256::zero());
        let access_list = request.access_list.unwrap_or(vec![]);
        let data = request.data.unwrap_or_default().into_vec();

        let transaction = match transaction_type.as_usize() as u8 {
            LEGACY_TX_TYPE => Eip155(Eip155Transaction {
                nonce,
                gas_price,
                gas,
                action,
                value,
                chain_id: Some(chain_id),
                data,
            }),
            EIP2930_TYPE => Eip2930(Eip2930Transaction {
                chain_id,
                nonce,
                gas_price,
                gas,
                action,
                value,
                data,
                access_list,
            }),
            EIP1559_TYPE => Eip1559(Eip1559Transaction {
                chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas,
                gas,
                action,
                value,
                data,
                access_list,
            }),
            x => {
                return Err(
                    format!("Unrecognized transaction type: {x}").into()
                );
            }
        };

        let from = request.from.unwrap_or(Address::zero());

        Ok(transaction.fake_sign_rpc(from.with_evm_space()))
    }
}
