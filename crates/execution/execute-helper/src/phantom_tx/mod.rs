mod recover;

use cfx_types::{Address, AddressSpaceUtil, Bloom, Space, U256};
use primitives::{
    transaction::eth_transaction::Eip155Transaction, Action, LogEntry, Receipt,
    SignedTransaction, TransactionStatus,
};

pub use recover::{build_bloom_and_recover_phantom, recover_phantom};

#[derive(Clone, Debug, Default)]
pub struct PhantomTransaction {
    pub from: Address,
    pub nonce: U256,
    pub action: Action,
    pub value: U256,
    pub data: Vec<u8>,

    pub log_bloom: Bloom,
    pub logs: Vec<LogEntry>,
    pub outcome_status: TransactionStatus,
}

impl PhantomTransaction {
    fn simple_transfer(
        from: Address, to: Address, nonce: U256, value: U256, data: Vec<u8>,
    ) -> PhantomTransaction {
        PhantomTransaction {
            from,
            nonce,
            action: Action::Call(to),
            value,
            data,
            outcome_status: TransactionStatus::Success,
            ..Default::default()
        }
    }
}

impl PhantomTransaction {
    pub fn into_eip155(self, chain_id: u32) -> SignedTransaction {
        let tx = Eip155Transaction {
            action: self.action,
            chain_id: Some(chain_id),
            data: self.data,
            gas_price: 0.into(),
            gas: 0.into(),
            nonce: self.nonce,
            value: self.value,
        };

        tx.fake_sign_phantom(self.from.with_space(Space::Ethereum))
    }

    pub fn into_receipt(self, accumulated_gas_used: U256) -> Receipt {
        Receipt {
            accumulated_gas_used,
            gas_fee: 0.into(),
            gas_sponsor_paid: false,
            log_bloom: self.log_bloom,
            logs: self.logs,
            outcome_status: self.outcome_status,
            storage_collateralized: vec![],
            storage_released: vec![],
            storage_sponsor_paid: false,
            burnt_gas_fee: None,
        }
    }
}
