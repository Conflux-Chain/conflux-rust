use crate::{
    utils::deserializer::deserialize_maybe_empty, SignedAuthorization,
    TestAuthorization,
};
use cfx_rpc_primitives::Bytes;
use cfx_types::{Address, H256, U256, U64};
use primitives::{
    transaction::{
        AccessList, Action, AuthorizationListItem, Eip1559Transaction,
        Eip155Transaction, Eip2930Transaction, Eip7702Transaction,
        EthereumTransaction,
    },
    SignedTransaction, Transaction as PrimitiveTx, TransactionWithSignature,
    TransactionWithSignatureSerializePart,
};
use rlp::Encodable;
use serde::Deserialize;

#[derive(Debug, PartialEq, Eq, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    #[serde(default, rename = "type")]
    pub tx_type: U64,
    pub chain_id: Option<U256>,
    pub nonce: U256,
    pub gas_price: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub gas_limit: U256,
    #[serde(default, deserialize_with = "deserialize_maybe_empty")]
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub v: U64,
    pub r: U256,
    pub s: U256,
    pub sender: Option<Address>,
    pub secret_key: Option<H256>,
    pub access_list: Option<AccessList>,
    pub max_fee_per_blob_gas: Option<U256>,
    pub blob_versioned_hashes: Option<Vec<H256>>,
    pub authorization_list: Option<Vec<TestAuthorization>>,
}

impl TryInto<SignedTransaction> for Transaction {
    type Error = String;

    fn try_into(self) -> Result<SignedTransaction, Self::Error> {
        let action = match self.to {
            Some(target) => Action::Call(target),
            None => Action::Create,
        };
        if self.tx_type.as_u32() > 0 && self.chain_id.is_none() {
            return Err("chain_id is required".into());
        }
        let eth_tx = match self.tx_type.as_u32() {
            0 => EthereumTransaction::Eip155(Eip155Transaction {
                nonce: self.nonce,
                gas_price: self.gas_price.unwrap_or_default(),
                gas: self.gas_limit,
                action,
                value: self.value,
                chain_id: self.chain_id.map(|chain_id| chain_id.as_u32()),
                data: self.data.0,
            }),
            1 => EthereumTransaction::Eip2930(Eip2930Transaction {
                nonce: self.nonce,
                gas_price: self.gas_price.unwrap_or_default(),
                gas: self.gas_limit,
                action,
                value: self.value,
                chain_id: self
                    .chain_id
                    .map(|chain_id| chain_id.as_u32())
                    .unwrap(),
                data: self.data.0,
                access_list: self.access_list.unwrap_or_default(),
            }),
            2 => EthereumTransaction::Eip1559(Eip1559Transaction {
                nonce: self.nonce,
                max_priority_fee_per_gas: self
                    .max_priority_fee_per_gas
                    .unwrap_or_default(),
                max_fee_per_gas: self.max_fee_per_gas.unwrap_or_default(),
                gas: self.gas_limit,
                action,
                value: self.value,
                chain_id: self
                    .chain_id
                    .map(|chain_id| chain_id.as_u32())
                    .unwrap(),
                data: self.data.0,
                access_list: self.access_list.unwrap_or_default(),
            }),
            3 => return Err("conflux does not support 4844 tx".into()),
            4 => {
                if self.authorization_list.is_none() {
                    return Err("7702 tx auth_list is required".into());
                }
                EthereumTransaction::Eip7702(Eip7702Transaction {
                    nonce: self.nonce,
                    max_priority_fee_per_gas: self
                        .max_priority_fee_per_gas
                        .unwrap_or_default(),
                    max_fee_per_gas: self.max_fee_per_gas.unwrap_or_default(),
                    gas: self.gas_limit,
                    destination: self.to.unwrap_or_default(),
                    value: self.value,
                    chain_id: self
                        .chain_id
                        .map(|chain_id| chain_id.as_u32())
                        .unwrap(),
                    data: self.data.0,
                    access_list: self.access_list.unwrap_or_default(),
                    authorization_list: self
                        .authorization_list
                        .unwrap()
                        .into_iter()
                        .map(|item| {
                            let signed_auth: SignedAuthorization = item.into();
                            AuthorizationListItem {
                                chain_id: signed_auth.inner().chain_id,
                                address: signed_auth.inner().address,
                                nonce: signed_auth.inner().nonce,
                                y_parity: signed_auth.y_parity(),
                                r: signed_auth.r(),
                                s: signed_auth.s(),
                            }
                        })
                        .collect(),
                })
            }
            _ => return Err("unsupported tx type".into()),
        };

        let tx = PrimitiveTx::Ethereum(eth_tx);
        if self.v > U64::from(u8::max_value()) {
            return Err("incorrect v value".into());
        }
        let tx_with_sig = TransactionWithSignatureSerializePart {
            unsigned: tx,
            v: self.v.as_u32() as u8,
            r: self.r,
            s: self.s,
        };

        let rlp_bytes = tx_with_sig.rlp_bytes();
        let rlp_size = rlp_bytes.len();
        let hash = keccak_hash::keccak(rlp_bytes);

        let signed_tx = TransactionWithSignature {
            transaction: tx_with_sig,
            hash,
            rlp_size: Some(rlp_size),
        };
        let public = signed_tx.recover_public();
        Ok(SignedTransaction {
            transaction: signed_tx,
            sender: self.sender.unwrap_or_default(),
            public: public.ok(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_basic() {
        let json_str = r#"{
            "type": "0x00",
            "chainId": "0x01",
            "nonce": "0x00",
            "gasPrice": "0x0a",
            "gasLimit": "0x07a120",
            "to": "0x0000000000000000000000000000000000001000",
            "value": "0x00",
            "data": "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            "v": "0x26",
            "r": "0xb71d8dd5ac327ec1b822930c066a9d0931a26f8529cbd0dca51a6a1f3fc508c9",
            "s": "0x63698823fb964779539d8fd4d016e7326cbd9dab987233458980d422776167b5",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
        }"#;

        let tx: Transaction = serde_json::from_str(json_str).unwrap();
        assert_eq!(tx.tx_type, U64::from(0));
        assert_eq!(tx.chain_id, Some(U256::from(1)));
        assert_eq!(tx.nonce, U256::from(0));
        assert_eq!(tx.v, U64::from(38));
        assert_eq!(tx.access_list, None);
    }

    #[test]
    fn recover_access_list_tx() {
        let json_str = r#"{
            "type": "0x01",
            "chainId": "0x01",
            "nonce": "0x00",
            "gasPrice": "0x07",
            "gasLimit": "0x04ef00",
            "to": "0x0000000000000000000000000000000000001000",
            "value": "0x01",
            "data": "0x",
            "accessList": [
                {
                    "address": "0x0000000000000000000000000000000000000000",
                    "storageKeys": [
                        "0x0000000000000000000000000000000000000000000000000000000000000000"
                    ]
                }
            ],
            "v": "0x00",
            "r": "0x81a25ffdb3797e6428f854c642e1884ee7b7be0c4ccbb7e989b70039b87e4450",
            "s": "0x2d25e40f45271d5f77735d06550dff43bf328190de034157cefec446855513d6",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
        }"#;

        let tx: Transaction = serde_json::from_str(json_str).unwrap();
        assert_eq!(tx.tx_type, U64::from(1));
        assert!(tx.access_list.is_some());
        assert_eq!(tx.access_list.unwrap().len(), 1);
    }

    #[test]
    fn recover_1559_tx() {
        let json_str = r#"{
            "type": "0x02",
            "chainId": "0x01",
            "nonce": "0x00",
            "maxPriorityFeePerGas": "0x00",
            "maxFeePerGas": "0x07",
            "gasLimit": "0x0f4240",
            "to": "0x0000000000000000000000000000000000001000",
            "value": "0x00",
            "data": "0x000000000000000000000000000000000000000000000000000000000000000c",
            "accessList": [],
            "v": "0x00",
            "r": "0x0250e37fb1094dca850d5e9930a67cfcbdfb10dd4e93d576c1add47ebcaa9087",
            "s": "0x77e2484f633730a17870768524826e03dbb3a1856b5b07b850631453167b42c5",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
        }"#;

        let tx: Transaction = serde_json::from_str(json_str).unwrap();
        assert_eq!(tx.tx_type, U64::from(2));
        assert_eq!(tx.max_fee_per_gas, Some(U256::from(7)));
    }

    #[test]
    fn recover_7702_tx() {
        let json_str = r#"{
            "type": "0x04",
            "chainId": "0x01",
            "nonce": "0x00",
            "maxPriorityFeePerGas": "0x00",
            "maxFeePerGas": "0x07",
            "gasLimit": "0x023a5a",
            "to": "0x0000000000000000000000000000000000001000",
            "value": "0x00",
            "data": "0x010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010100",
            "accessList": [],
            "v": "0x01",
            "r": "0x3f1b651968d0fb5693206b5f7ece4b4194828417e03abc35f99657e3a39bf485",
            "s": "0x69b6b8c3bc51916a47bffe07298daf32177f39cc14e1d043c55d46ebca4e67b8",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "authorizationList": [
                {
                    "chainId": "0x00",
                    "address": "0x0000000000000000000000000000000000000001",
                    "nonce": "0x00",
                    "v": "0x00",
                    "r": "0x33a629f82b5aaff5b4bfe6b9ab53bb3646b92cda403d7c834f72c9a5073aec20",
                    "s": "0x16902e4a3c089e05d649cab6bd74b6f424fae0eefad3a4944fa452ff7413b5d3",
                    "signer": "0x8a0a19589531694250d570040a0c4b74576919b8",
                    "yParity": "0x00"
                }
            ]
        }"#;

        let tx: Transaction = serde_json::from_str(json_str).unwrap();
        assert_eq!(tx.tx_type, U64::from(4));
        assert!(tx.authorization_list.is_some());
        assert_eq!(tx.authorization_list.unwrap().len(), 1);
    }

    #[test]
    fn recover_4844_tx() {
        let json_str = r#"{
            "type": "0x03",
            "chainId": "0x01",
            "nonce": "0x00",
            "maxPriorityFeePerGas": "0x00",
            "maxFeePerGas": "0x07",
            "gasLimit": "0x0f4240",
            "to": "0x000f3df6d732807ef1319fb7b8bb8522d0beac02",
            "value": "0x00",
            "data": "0x000000000000000000000000000000000000000000000000000000000000000c",
            "accessList": [],
            "maxFeePerBlobGas": "0x01",
            "blobVersionedHashes": [
                "0x0100000000000000000000000000000000000000000000000000000000000000"
            ],
            "v": "0x01",
            "r": "0x53116c986dc393633b36cacf6e2c5cf896531ffed002ba696a1bab16db1ef4f4",
            "s": "0x45d8f72ef3b93897c58143b6b4368c56947344b2770695dccc26aa6d2f35b248",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
        }"#;

        let tx: Transaction = serde_json::from_str(json_str).unwrap();
        assert_eq!(tx.tx_type, U64::from(3));
        assert!(tx.blob_versioned_hashes.is_some());
        assert_eq!(tx.blob_versioned_hashes.unwrap().len(), 1);
        assert_eq!(tx.max_fee_per_blob_gas, Some(U256::from(1)));
    }
}
