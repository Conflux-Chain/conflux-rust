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

use crate::Error;
use alloy_rpc_types::TransactionInput;
use cfx_parameters::block::DEFAULT_TARGET_BLOCK_GAS_LIMIT;
use cfx_types::{Address, AddressSpaceUtil, H160, U256, U64};
use primitives::{
    transaction::{
        Action, Eip1559Transaction, Eip155Transaction, Eip2930Transaction,
        EthereumTransaction::*, SignedTransaction, EIP1559_TYPE, EIP2930_TYPE,
        LEGACY_TX_TYPE,
    },
    AccessList,
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_ETH_GAS_CALL_REQUEST: u64 =
    DEFAULT_TARGET_BLOCK_GAS_LIMIT * 5 / 10;

/// Call request
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize, Clone)]
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
    ///
    pub max_priority_fee_per_gas: Option<U256>,
    /// Gas
    pub gas: Option<U256>,
    /// Value
    pub value: Option<U256>,
    ///
    #[serde(default, flatten)]
    pub input: TransactionInput,
    /// Nonce
    pub nonce: Option<U256>,
    /// Access list
    pub access_list: Option<AccessList>,
    #[serde(rename = "type")]
    pub transaction_type: Option<U64>,
    ///
    pub chain_id: Option<U256>,
}

impl TransactionRequest {
    pub fn unset_zero_gas_and_price(&mut self) {
        if self.gas_price == Some(U256::zero()) {
            self.gas_price = None;
        }

        if self.gas == Some(U256::zero()) {
            self.gas = None;
        }
    }

    pub fn transaction_type(&self) -> u8 {
        if let Some(tx_type) = self.transaction_type {
            tx_type.as_usize() as u8
        } else {
            if self.max_fee_per_gas.is_some()
                || self.max_priority_fee_per_gas.is_some()
            {
                EIP1559_TYPE
            } else if self.access_list.is_some() {
                EIP2930_TYPE
            } else {
                LEGACY_TX_TYPE
            }
        }
    }

    pub fn has_gas_price(&self) -> bool {
        self.gas_price.is_some()
            || self.max_fee_per_gas.is_some()
            || self.max_priority_fee_per_gas.is_some()
    }

    pub fn sign_call(
        self, chain_id: u32, max_gas: Option<U256>,
    ) -> Result<SignedTransaction, Error> {
        let request = self;
        let max_gas = max_gas.unwrap_or(DEFAULT_ETH_GAS_CALL_REQUEST.into());
        let gas = request.gas.unwrap_or(max_gas);
        if gas > max_gas {
            return Err(Error::InvalidParams(
                "gas".into(),
                "specified gas is larger than max gas".to_string(),
            ));
        }

        let nonce = request.nonce.unwrap_or_default();
        let action =
            request.to.map_or(Action::Create, |addr| Action::Call(addr));
        let value = request.value.unwrap_or_default();

        let transaction_type = request.transaction_type();

        let gas_price = request.gas_price.unwrap_or(1.into());
        let max_fee_per_gas = request
            .max_fee_per_gas
            .or(request.max_priority_fee_per_gas)
            .unwrap_or(gas_price);
        let max_priority_fee_per_gas =
            request.max_priority_fee_per_gas.unwrap_or(U256::zero());
        let access_list = request.access_list.unwrap_or(vec![]);
        let data = request
            .input
            .try_into_unique_input()
            .map_err(|e| {
                Error::InvalidParams("tx.input".to_string(), e.to_string())
            })?
            .unwrap_or_default()
            .into();

        let transaction = match transaction_type {
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
            _ => {
                return Err(Error::InvalidParams(
                    "type".to_string(),
                    "Unrecognized transaction type".to_string(),
                ));
            }
        };

        let from = request.from.unwrap_or(Address::zero());

        Ok(transaction.fake_sign_rpc(from.with_evm_space()))
    }
}
