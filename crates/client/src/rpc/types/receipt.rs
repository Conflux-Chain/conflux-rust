// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{Log, RpcAddress};
use cfx_addr::Network;
use cfx_types::{
    address_util::AddressUtil, Bloom, Space, SpaceMap, H256, U256, U64,
};
use cfx_vm_types::{contract_address, CreateContractAddress};
use primitives::{
    receipt::{
        Receipt as PrimitiveReceipt, StorageChange as PrimitiveStorageChange,
    },
    transaction::Action,
    SignedTransaction as PrimitiveTransaction, Transaction, TransactionIndex,
    TransactionStatus,
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
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
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
    /// The total gas used (not gas charged) in the block following execution
    /// of the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accumulated_gas_used: Option<U256>,
    /// The gas fee charged in the execution of the transaction.
    pub gas_fee: U256,
    pub effective_gas_price: U256,
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
    /// Transaction space.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<Space>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burnt_gas_fee: Option<U256>,
}

impl Receipt {
    pub fn new(
        transaction: PrimitiveTransaction, receipt: PrimitiveReceipt,
        transaction_index: TransactionIndex, prior_gas_used: U256,
        epoch_number: Option<u64>, block_number: u64,
        maybe_base_price: Option<SpaceMap<U256>>,
        maybe_state_root: Option<H256>, tx_exec_error_msg: Option<String>,
        network: Network, include_eth_receipt: bool,
        include_accumulated_gas_used: bool,
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

        let (address, action, space) = match transaction.unsigned {
            Transaction::Native(ref unsigned) => {
                if Action::Create == *unsigned.action()
                    && outcome_status == TransactionStatus::Success
                {
                    let (mut created_address, _) = contract_address(
                        CreateContractAddress::FromSenderNonceAndCodeHash,
                        block_number.into(),
                        &transaction.sender,
                        unsigned.nonce(),
                        unsigned.data(),
                    );
                    created_address.set_contract_type_bits();
                    let address = Some(RpcAddress::try_from_h160(
                        created_address,
                        network,
                    )?);
                    (address, unsigned.action().clone(), Space::Native)
                } else {
                    (None, unsigned.action().clone(), Space::Native)
                }
            }
            Transaction::Ethereum(ref unsigned) => {
                if include_eth_receipt {
                    if Action::Create == *unsigned.action()
                        && outcome_status == TransactionStatus::Success
                    {
                        let (created_address, _) = contract_address(
                            CreateContractAddress::FromSenderNonce,
                            0,
                            &transaction.sender,
                            unsigned.nonce(),
                            unsigned.data(),
                        );
                        let address = Some(RpcAddress::try_from_h160(
                            created_address,
                            network,
                        )?);
                        (address, unsigned.action().clone(), Space::Ethereum)
                    } else {
                        (None, unsigned.action().clone(), Space::Ethereum)
                    }
                } else {
                    bail!(format!("Does not support EIP-155 transaction in Conflux space RPC. get_receipt for tx: {:?}",transaction));
                }
            }
        };

        // this is an array, but it will only have at most one element:
        // the storage collateral of the sender address.
        let storage_collateralized = storage_collateralized
            .get(0)
            .map(|sc| sc.collaterals)
            .map(Into::into)
            .unwrap_or_default();

        let effective_gas_price = if let Some(base_price) = maybe_base_price {
            let base_price = base_price[transaction.space()];
            if *transaction.gas_price() < base_price {
                *transaction.gas_price()
            } else {
                transaction.effective_gas_price(&base_price)
            }
        } else {
            *transaction.gas_price()
        };

        Ok(Receipt {
            transaction_type: Some(U64::from(transaction.type_id())),
            transaction_hash: transaction.hash.into(),
            index: U64::from(
                transaction_index
                    .rpc_index
                    // FIXME(thegaram): this is triggered on light nodes, and
                    // maybe in some other cases as well.
                    // is there a better way to handle this?
                    .unwrap_or(transaction_index.real_index),
            ),
            block_hash: transaction_index.block_hash.into(),
            gas_used: (accumulated_gas_used - prior_gas_used).into(),
            accumulated_gas_used: if include_accumulated_gas_used {
                accumulated_gas_used.into()
            } else {
                None
            },
            gas_fee: gas_fee.into(),
            burnt_gas_fee: receipt.burnt_gas_fee,
            effective_gas_price,
            from: RpcAddress::try_from_h160(transaction.sender, network)?,
            to: match &action {
                Action::Create => None,
                Action::Call(address) => {
                    Some(RpcAddress::try_from_h160(address.clone(), network)?)
                }
            },
            outcome_status: U64::from(outcome_status.in_space(space)),
            contract_created: address,
            logs: logs
                .into_iter()
                .filter(|l| {
                    if include_eth_receipt {
                        true
                    } else {
                        l.space == Space::Native
                    }
                })
                .map(|l| Log::try_from(l, network, include_eth_receipt))
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
            space: if include_eth_receipt {
                Some(space)
            } else {
                None
            },
        })
    }
}
