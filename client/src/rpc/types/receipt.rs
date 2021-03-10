// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{Log, RpcAddress};
use cfx_addr::Network;
use cfx_types::{Bloom, H256, U256, U64};
use cfxcore::{executive::contract_address, vm::CreateContractAddress};
use primitives::{
    receipt::{
        Receipt as PrimitiveReceipt, StorageChange as PrimitiveStorageChange,
    },
    transaction::Action,
    SignedTransaction as PrimitiveTransaction, TransactionIndex,
};
use serde_derive::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChange {
    pub address: RpcAddress,
    pub collaterals: U64,
}

impl StorageChange {
    pub fn try_from(
        sc: PrimitiveStorageChange, network: Network,
    ) -> Result<Self, String> {
        Ok(Self {
            address: RpcAddress::try_from_h160(sc.address, network)?,
            collaterals: sc.collaterals,
        })
    }
}

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    /// Transaction hash.
    pub transaction_hash: H256,
    /// Transaction index within the block.
    pub index: U64,
    /// Block hash.
    pub block_hash: H256,
    /// Epoch number where this transaction was in.
    pub epoch_number: Option<U64>,
    /// Address of the sender.
    pub from: RpcAddress,
    /// Address of the receiver, null when it's a contract creation
    /// transaction.
    pub to: Option<RpcAddress>,
    /// The gas used in the execution of the transaction.
    pub gas_used: U256,
    /// The gas fee charged in the execution of the transaction.
    pub gas_fee: U256,
    /// Address of contract created if the transaction action is create.
    pub contract_created: Option<RpcAddress>,
    /// Array of log objects, which this transaction generated.
    pub logs: Vec<Log>,
    /// Bloom filter for light clients to quickly retrieve related logs.
    pub logs_bloom: Bloom,
    /// State root.
    pub state_root: H256,
    /// Transaction outcome.
    pub outcome_status: U64,
    /// Detailed error message if tx execution is unsuccessful. Error message
    /// is None if tx execution is successful or it can not be offered.
    /// Error message can not be offered by light client.
    pub tx_exec_error_msg: Option<String>,
    // Whether gas costs were covered by the sponsor.
    pub gas_covered_by_sponsor: bool,
    // Whether storage costs were covered by the sponsor.
    pub storage_covered_by_sponsor: bool,
    // The amount of storage collateralized by the sender.
    pub storage_collateralized: U64,
    // Storage collaterals released during the execution of the transaction.
    pub storage_released: Vec<StorageChange>,
}

impl Receipt {
    pub fn new(
        transaction: PrimitiveTransaction, receipt: PrimitiveReceipt,
        transaction_index: TransactionIndex, prior_gas_used: U256,
        epoch_number: Option<u64>, block_number: u64,
        maybe_state_root: Option<H256>, tx_exec_error_msg: Option<String>,
        network: Network,
    ) -> Result<Receipt, String> {
        let PrimitiveReceipt {
            accumulated_gas_used,
            gas_fee,
            gas_sponsor_paid,
            log_bloom,
            logs,
            outcome_status,
            storage_collateralized,
            storage_released,
            storage_sponsor_paid,
            ..
        } = receipt;

        let mut address = None;
        if Action::Create == transaction.action && outcome_status == 0 {
            let (created_address, _) = contract_address(
                CreateContractAddress::FromSenderNonceAndCodeHash,
                block_number.into(),
                &transaction.sender,
                &transaction.nonce,
                &transaction.data,
            );
            address =
                Some(RpcAddress::try_from_h160(created_address, network)?);
        }

        // this is an array, but it will only have at most one element:
        // the storage collateral of the sender address.
        let storage_collateralized = storage_collateralized
            .get(0)
            .map(|sc| sc.collaterals)
            .map(Into::into)
            .unwrap_or_default();

        Ok(Receipt {
            transaction_hash: transaction.hash.into(),
            index: U64::from(transaction_index.index),
            block_hash: transaction_index.block_hash.into(),
            gas_used: (accumulated_gas_used - prior_gas_used).into(),
            gas_fee: gas_fee.into(),
            from: RpcAddress::try_from_h160(transaction.sender, network)?,
            to: match &transaction.action {
                Action::Create => None,
                Action::Call(address) => {
                    Some(RpcAddress::try_from_h160(address.clone(), network)?)
                }
            },
            outcome_status: U64::from(outcome_status),
            contract_created: address,
            logs: logs
                .into_iter()
                .map(|l| Log::try_from(l, network))
                .collect::<Result<_, _>>()?,
            logs_bloom: log_bloom,
            state_root: maybe_state_root
                .map_or_else(Default::default, Into::into),
            epoch_number: epoch_number.map(U64::from),
            tx_exec_error_msg,
            gas_covered_by_sponsor: gas_sponsor_paid,
            storage_covered_by_sponsor: storage_sponsor_paid,
            storage_collateralized,
            storage_released: storage_released
                .into_iter()
                .map(|sc| StorageChange::try_from(sc, network))
                .collect::<Result<_, _>>()?,
        })
    }
}
