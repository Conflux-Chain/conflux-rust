// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::{receipt::Receipt, Bytes};
use cfx_types::{H160, H256, U256, U64};
use cfxcore_accounts::AccountProvider;
use cfxkey::{Error, Password};
use primitives::{
    transaction::Action, SignedTransaction,
    Transaction as PrimitiveTransaction, TransactionIndex,
    TransactionWithSignature, TransactionWithSignatureSerializePart,
};
use std::sync::Arc;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub hash: H256,
    pub nonce: U256,
    pub block_hash: Option<H256>,
    pub transaction_index: Option<U64>,
    pub from: H160,
    pub to: Option<H160>,
    pub value: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub contract_created: Option<H160>,
    pub data: Bytes,
    pub storage_limit: U256,
    pub epoch_height: U256,
    pub chain_id: U256,
    pub status: Option<U64>,
    /// The standardised V field of the signature.
    pub v: U256,
    /// The R field of the signature.
    pub r: U256,
    /// The S field of the signature.
    pub s: U256,
}

pub enum PackedOrExecuted {
    Packed(TransactionIndex),
    Executed(Receipt),
}

impl Transaction {
    pub fn from_signed(
        t: &SignedTransaction,
        maybe_packed_or_executed: Option<PackedOrExecuted>,
    ) -> Transaction
    {
        let mut contract_created = None;
        let mut status: Option<U64> = None;
        let mut block_hash = None;
        let mut transaction_index = None;
        match maybe_packed_or_executed {
            None => {}
            Some(PackedOrExecuted::Packed(tx_index)) => {
                block_hash = Some(tx_index.block_hash);
                transaction_index = Some(tx_index.index.into());
            }
            Some(PackedOrExecuted::Executed(receipt)) => {
                block_hash = Some(receipt.block_hash);
                transaction_index = Some(receipt.index.into());
                if let Some(ref address) = receipt.contract_created {
                    contract_created = Some(address.clone().into());
                }
                status = Some(receipt.outcome_status);
            }
        }
        Transaction {
            hash: t.transaction.hash().into(),
            nonce: t.nonce.into(),
            block_hash,
            transaction_index,
            status,
            contract_created,
            from: t.sender().into(),
            to: match t.action {
                Action::Create => None,
                Action::Call(ref address) => Some(address.clone().into()),
            },
            value: t.value.into(),
            gas_price: t.gas_price.into(),
            gas: t.gas.into(),
            data: t.data.clone().into(),
            storage_limit: t.storage_limit.into(),
            epoch_height: t.epoch_height.into(),
            chain_id: t.chain_id.into(),
            v: t.transaction.v.into(),
            r: t.transaction.r.into(),
            s: t.transaction.s.into(),
        }
    }

    pub fn into_signed(self) -> Result<SignedTransaction, Error> {
        let tx_with_sig = TransactionWithSignature {
            transaction: TransactionWithSignatureSerializePart {
                unsigned: PrimitiveTransaction {
                    nonce: self.nonce.into(),
                    gas_price: self.gas_price.into(),
                    gas: self.gas.into(),
                    action: match self.to {
                        None => Action::Create,
                        Some(address) => Action::Call(address.into()),
                    },
                    value: self.value.into(),
                    storage_limit: self.storage_limit.as_u64(),
                    epoch_height: self.epoch_height.as_u64(),
                    chain_id: self.chain_id.as_u32(),
                    data: self.data.into(),
                },
                v: self.v.as_usize() as u8,
                r: self.r.into(),
                s: self.s.into(),
            },
            hash: self.hash.into(),
            rlp_size: None,
        };
        let public = tx_with_sig.recover_public()?;
        Ok(SignedTransaction::new(public, tx_with_sig))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTxRequest {
    pub from: H160,
    pub to: Option<H160>,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Option<Bytes>,
    pub nonce: Option<U256>,
    pub storage_limit: Option<U256>,
    pub chain_id: Option<U256>,
    pub epoch_height: Option<U256>,
}

impl SendTxRequest {
    pub fn sign_with(
        self, best_epoch_height: u64, chain_id: u32, password: Option<String>,
        accounts: Arc<AccountProvider>,
    ) -> Result<TransactionWithSignature, String>
    {
        let tx = PrimitiveTransaction {
            nonce: self.nonce.unwrap_or_default().into(),
            gas_price: self.gas_price.into(),
            gas: self.gas.into(),
            action: match self.to {
                None => Action::Create,
                Some(address) => Action::Call(address.into()),
            },
            value: self.value.into(),
            storage_limit: self
                .storage_limit
                .unwrap_or(std::u64::MAX.into())
                .as_usize() as u64,
            epoch_height: self
                .epoch_height
                .unwrap_or(best_epoch_height.into())
                .as_usize() as u64,
            chain_id: self.chain_id.unwrap_or(chain_id.into()).as_u32(),
            data: self.data.unwrap_or(Bytes::new(vec![])).into(),
        };

        let password = password.map(Password::from);
        let sig = accounts
            .sign(self.from.into(), password, tx.hash())
            .map_err(|e| format!("failed to sign transaction: {:?}", e))?;

        Ok(tx.with_signature(sig))
    }
}

#[derive(Default, Serialize)]
pub struct TxWithPoolInfo {
    pub exist: bool,
    pub packed: bool,
    pub local_nonce: U256,
    pub local_balance: U256,
    pub state_nonce: U256,
    pub state_balance: U256,
    pub local_balance_enough: bool,
    pub state_balance_enough: bool,
}

#[derive(Default, Serialize)]
pub struct TxPoolPendingInfo {
    pub pending_count: usize,
    pub min_nonce: U256,
    pub max_nonce: U256,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use super::*;
    use cfxkey::Secret;
    use cfx_types::{H160, H256, U256, Bloom};
    use crate::rpc::types::{Transaction, PackedOrExecuted};
    use serde_json;
    use primitives::{transaction::Action,
                     SignedTransaction,
                     Transaction as PrimitiveTransaction,
                     TransactionWithSignature,
                     TransactionWithSignatureSerializePart,
                     TransactionIndex};

    #[test]
    fn test_transaction_serialize() {
        let transaction = Transaction{
            hash: H256([0xff;32]),
            nonce: U256::one(),
            block_hash: None,
            transaction_index: None,
            from: H160([0xff;20]),
            to: None,
            value: U256::one(),
            gas_price: U256::one(),
            gas: U256::one(),
            contract_created: None,
            data: Default::default(),
            storage_limit: U256::one(),
            epoch_height: U256::one(),
            chain_id: U256::one(),
            status: None,
            v: U256::one(),
            r: U256::one(),
            s: U256::one()
        };
        let serialize = serde_json::to_string(&transaction).unwrap();
        assert_eq!(serialize,
                   "{\"hash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"nonce\":\"0x1\",\"blockHash\":null,\"transactionIndex\":null,\"from\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"to\":null,\"value\":\"0x1\",\"gasPrice\":\"0x1\",\"gas\":\"0x1\",\"contractCreated\":null,\"data\":\"0x\",\"storageLimit\":\"0x1\",\"epochHeight\":\"0x1\",\"chainId\":\"0x1\",\"status\":null,\"v\":\"0x1\",\"r\":\"0x1\",\"s\":\"0x1\"}");
    }
    #[test]
    fn test_transaction_deserialize() {
        let serialize = "{\"hash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"nonce\":\"0x1\",\"blockHash\":null,\"transactionIndex\":null,\"from\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"to\":null,\"value\":\"0x1\",\"gasPrice\":\"0x1\",\"gas\":\"0x1\",\"contractCreated\":null,\"data\":\"0x\",\"storageLimit\":\"0x1\",\"epochHeight\":\"0x1\",\"chainId\":\"0x1\",\"status\":null,\"v\":\"0x1\",\"r\":\"0x1\",\"s\":\"0x1\"}";
        let deserialize: Transaction = serde_json::from_str(serialize).unwrap();
        let transaction = Transaction{
            hash: H256([0xff;32]),
            nonce: U256::one(),
            block_hash: None,
            transaction_index: None,
            from: H160([0xff;20]),
            to: None,
            value: U256::one(),
            gas_price: U256::one(),
            gas: U256::one(),
            contract_created: None,
            data: Default::default(),
            storage_limit: U256::one(),
            epoch_height: U256::one(),
            chain_id: U256::one(),
            status: None,
            v: U256::one(),
            r: U256::one(),
            s: U256::one()
        };
        assert_eq!(deserialize,transaction);
    }
    #[test]
    fn test_transaction_from_signed_default() {
        let transaction = Transaction::default();
        let sign_transaction = SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: PrimitiveTransaction {
                        nonce: transaction.nonce.into(),
                        gas_price: transaction.gas_price.into(),
                        gas: transaction.gas.into(),
                        action: match transaction.to {
                            None => Action::Create,
                            Some(address) => Action::Call(address.into()),
                        },
                        value: transaction.value.into(),
                        storage_limit: transaction.storage_limit.as_u64(),
                        epoch_height: transaction.epoch_height.as_u64(),
                        chain_id: transaction.chain_id.as_u32(),
                        data: transaction.data.into(),
                    },
                    r: U256::one(),
                    s: U256::one(),
                    v: 0,
                },
                hash: H256::zero(),
                rlp_size: None,
            },
            sender: H160([0xff; 20]),
            public: None,
        };
        let t:Transaction =
            Transaction::from_signed(&sign_transaction,None);
        let transaction_from_signed = serde_json::to_string(&t).unwrap();
        assert_eq!(transaction_from_signed,
                   r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":null,"transactionIndex":null,"from":"0xffffffffffffffffffffffffffffffffffffffff","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","contractCreated":null,"data":"0x","storageLimit":"0x0","epochHeight":"0x0","chainId":"0x0","status":null,"v":"0x0","r":"0x1","s":"0x1"}"#);
    }

    #[test]
    fn test_transaction_from_signed_executed() {
        let transaction = Transaction::default();
        let sign_transaction = SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: PrimitiveTransaction {
                        nonce: transaction.nonce.into(),
                        gas_price: transaction.gas_price.into(),
                        gas: transaction.gas.into(),
                        action: match transaction.to {
                            None => Action::Create,
                            Some(address) => Action::Call(address.into()),
                        },
                        value: transaction.value.into(),
                        storage_limit: transaction.storage_limit.as_u64(),
                        epoch_height: transaction.epoch_height.as_u64(),
                        chain_id: transaction.chain_id.as_u32(),
                        data: transaction.data.into(),
                    },
                    r: U256::one(),
                    s: U256::one(),
                    v: 0,
                },
                hash: H256::zero(),
                rlp_size: None,
            },
            sender: H160([0xff; 20]),
            public: None,
        };
        let bloom: [u8; 256] = [0;256];
        let receipt = Some(PackedOrExecuted::Executed(Receipt{
            transaction_hash: H256::default(),
            block_hash: H256::default(),
            epoch_number: None,
            from: H160::default(),
            to: None,
            gas_used: U256::default(),
            index: U64::default(),
            outcome_status: U64::default(),
            contract_created: None,
            logs: vec![],
            logs_bloom: Bloom(bloom),  // to be fixed, [U8;256] expected
            gas_fee: U256::default(),
            state_root: H256::default()
        }));
        let t:Transaction =
            Transaction::from_signed(&sign_transaction,receipt);
        let transaction_from_signed = serde_json::to_string(&t).unwrap();
        assert_eq!(transaction_from_signed,
                   r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionIndex":"0x0","from":"0xffffffffffffffffffffffffffffffffffffffff","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","contractCreated":null,"data":"0x","storageLimit":"0x0","epochHeight":"0x0","chainId":"0x0","status":"0x0","v":"0x0","r":"0x1","s":"0x1"}"#);
    }

    #[test]
    fn test_transaction_from_signed_packed() {
        let transaction = Transaction::default();
        let sign_transaction = SignedTransaction {
            transaction: TransactionWithSignature {
                transaction: TransactionWithSignatureSerializePart {
                    unsigned: PrimitiveTransaction {
                        nonce: transaction.nonce.into(),
                        gas_price: transaction.gas_price.into(),
                        gas: transaction.gas.into(),
                        action: match transaction.to {
                            None => Action::Create,
                            Some(address) => Action::Call(address.into()),
                        },
                        value: transaction.value.into(),
                        storage_limit: transaction.storage_limit.as_u64(),
                        epoch_height: transaction.epoch_height.as_u64(),
                        chain_id: transaction.chain_id.as_u32(),
                        data: transaction.data.into(),
                    },
                    r: U256::one(),
                    s: U256::one(),
                    v: 0,
                },
                hash: H256::zero(),
                rlp_size: None,
            },
            sender: H160([0xff; 20]),
            public: None,
        };
        let transaction_index = Some(PackedOrExecuted::Packed(TransactionIndex{
            block_hash: H256::default(),
            index: 0,
        }));
        let t:Transaction =
            Transaction::from_signed(&sign_transaction,transaction_index);
        let transaction_from_signed = serde_json::to_string(&t).unwrap();
        assert_eq!(transaction_from_signed,
                   r#"{"hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0","blockHash":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionIndex":"0x0","from":"0xffffffffffffffffffffffffffffffffffffffff","to":null,"value":"0x0","gasPrice":"0x0","gas":"0x0","contractCreated":null,"data":"0x","storageLimit":"0x0","epochHeight":"0x0","chainId":"0x0","status":null,"v":"0x0","r":"0x1","s":"0x1"}"#);
    }

    #[test]
    fn test_transaction_into_signed() {
        let x = Transaction::into_signed(Transaction::default());
        let my_transaction = Transaction{
            hash:H256([0xff;32]),
            nonce: U256::one(),
            block_hash: None,
            transaction_index: None,
            from: H160([0xff; 20]),
            to: Some(H160([0xff; 20])),
            value: U256::one(),
            gas_price: U256::one(),
            gas: U256::one(),
            contract_created: None,
            data: Default::default(),
            storage_limit: U256::one(),
            epoch_height: U256::one(),
            chain_id: U256::one(),
            status: None,
            v: U256::one(),
            r: U256::one(),
            s: U256::one(),
        };
        let y = Transaction::into_signed(my_transaction);
        assert_eq!(y.is_ok(), true);
        let sign_transaction_info =  serde_json::to_string(&y.unwrap()).unwrap();
        assert_eq!(x.is_err(), true);
        assert_eq!(sign_transaction_info,
                   "{\"transaction\":{\"transaction\":{\"unsigned\":{\"nonce\":\"0x1\",\"gasPrice\":\"0x1\",\"gas\":\"0x1\",\"action\":{\"Call\":\"0xffffffffffffffffffffffffffffffffffffffff\"},\"value\":\"0x1\",\"storageLimit\":1,\"epochHeight\":1,\"chainId\":1,\"data\":[]},\"v\":1,\"r\":\"0x1\",\"s\":\"0x1\"}},\"sender\":\"0x1096d41a4a90d96f4123c713d1a9435c8ea27e41\",\"public\":\"0x8327f80b1ecf0048e093d1a9ff452cf1a4fa647fbb2069c59617d4b0a01ddfd5caedfbd5a4945913a2d31f4b41aeab3d25f88588ee8df9e58e859c473c766ca3\"}");
    }

    #[test]
    fn test_send_tx_request_sign_with_error() {
        let request = SendTxRequest{
            from: H160([0xff;20]),
            to: None,
            gas: U256::one(),
            gas_price: U256::one(),
            value: U256::one(),
            data: None,
            nonce: None,
            storage_limit: None,
            chain_id: None,
            epoch_height: None
        };
        let ap = AccountProvider::transient_provider();
        let x = SendTxRequest::sign_with(
            request,
            U256::one().as_u64(),
            U256::one().as_u32(),
            None,
            Arc::new(ap)
        );
        assert_eq!(x.is_err(), true);
        let request2 = SendTxRequest{
            from: H160([0xff;20]),
            to: None,
            gas: U256::one(),
            gas_price: U256::one(),
            value: U256::one(),
            data: None,
            nonce: None,
            storage_limit: None,
            chain_id: None,
            epoch_height: None
        };
        let ap2 = AccountProvider::transient_provider();
        let y = SendTxRequest::sign_with(
            request2,
            U256::one().as_u64(),
            U256::one().as_u32(),
            Some(String::from("this is the password")),
            Arc::new(ap2)
        );
        assert_eq!(y.is_ok(), false);
    }
    #[test]
    fn test_send_tx_request_sign_with_ok() {
        let ap3 = AccountProvider::transient_provider();
        let secret = Secret::from_str(
            "a100df7a048e50ed308ea696dc600215098141cb391e9527329df289f9383f65",
        ).unwrap();
        let address = AccountProvider::insert_account(&ap3,secret,&"password".into()).unwrap();
        let request3 = SendTxRequest{
            from: address,
            to: None,
            gas: U256::one(),
            gas_price: U256::one(),
            value: U256::one(),
            data: Some(Bytes(vec![])),
            nonce: Some(U256::one()),
            storage_limit: Some(U256::one()),
            chain_id: Some(U256::one()),
            epoch_height: Some(U256::one())
        };
        let z = SendTxRequest::sign_with(
            request3,
            U256::one().as_u64(),
            U256::one().as_u32(),
            Some("password".into()),//Some("this is the password".into()),
            Arc::new(ap3)
        );
        assert_eq!(z.is_err(), false);
        let info = serde_json::to_string(&z).unwrap();
        assert_eq!(info,
                   "{\"Ok\":{\"transaction\":{\"unsigned\":{\"nonce\":\"0x1\",\"gasPrice\":\"0x1\",\"gas\":\"0x1\",\"action\":\"Create\",\"value\":\"0x1\",\"storageLimit\":1,\"epochHeight\":1,\"chainId\":1,\"data\":[]},\"v\":0,\"r\":\"0x48c606475f4a90b89697105a246b0b95009ffe596b468de00bc3f6289cc884ff\",\"s\":\"0x19f38170561228fc31613626d9b8fdde18796ba8ae9c3c5470764260cbb525cf\"}}}");
    }
    #[test]
    fn test_tx_pool_info() {
        let tx_pool_info = TxWithPoolInfo{
            exist: false,
            packed: false,
            local_nonce: Default::default(),
            local_balance: Default::default(),
            state_nonce: Default::default(),
            state_balance: Default::default(),
            local_balance_enough: false,
            state_balance_enough: false
        };
        let info = serde_json::to_string(&tx_pool_info).unwrap();
        assert_eq!(info,"{\"exist\":false,\"packed\":false,\"local_nonce\":\"0x0\",\"local_balance\":\"0x0\",\"state_nonce\":\"0x0\",\"state_balance\":\"0x0\",\"local_balance_enough\":false,\"state_balance_enough\":false}");
    }
    #[test]
    fn test_tx_pool_pending_info () {
        let pending_info = TxPoolPendingInfo{
            pending_count: 0,
            min_nonce: Default::default(),
            max_nonce: Default::default()
        };
        let info = serde_json::to_string(&pending_info).unwrap();
        assert_eq!(info,"{\"pending_count\":0,\"min_nonce\":\"0x0\",\"max_nonce\":\"0x0\"}");
    }
}