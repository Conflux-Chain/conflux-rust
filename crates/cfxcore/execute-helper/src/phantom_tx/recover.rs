use cfx_executor::internal_contract::{
    cross_space_events::*, SolidityEventTrait,
};
use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_types::{Address, Bloom, Space, H256, U256};
use primitives::{log_entry::build_bloom, Action, LogEntry, TransactionStatus};
use solidity_abi::{ABIDecodable, ABIEncodable};

use super::PhantomTransaction;

type Bytes20 = [u8; 20];

pub fn build_bloom_and_recover_phantom(
    logs: &[LogEntry], tx_hash: H256,
) -> (Vec<PhantomTransaction>, Bloom) {
    (recover_phantom(logs, tx_hash), build_bloom(logs))
}

pub fn recover_phantom(
    logs: &[LogEntry], tx_hash: H256,
) -> Vec<PhantomTransaction> {
    let mut phantom_txs: Vec<PhantomTransaction> = Default::default();
    let mut maybe_working_tx: Option<PhantomTransaction> = None;
    let mut cross_space_nonce = 0u32;
    for log in logs.iter() {
        if log.address == CROSS_SPACE_CONTRACT_ADDRESS {
            let event_sig = log.topics.first().unwrap();
            if event_sig == &CallEvent::EVENT_SIG
                || event_sig == &CreateEvent::EVENT_SIG
            {
                assert!(maybe_working_tx.is_none());

                let from = Address::from(
                    Bytes20::abi_decode(&log.topics[1].as_ref()).unwrap(),
                );
                let to = Address::from(
                    Bytes20::abi_decode(&log.topics[2].as_ref()).unwrap(),
                );
                let (value, nonce, data): (_, _, Vec<u8>) =
                    ABIDecodable::abi_decode(&log.data).unwrap();

                let is_create = event_sig == &CreateEvent::EVENT_SIG;
                let action = if is_create {
                    Action::Create
                } else {
                    Action::Call(to)
                };
                // The first phantom transaction for cross-space call, transfer
                // balance and gas fee from the zero address to the mapped
                // sender
                phantom_txs.push(PhantomTransaction::simple_transfer(
                    /* from */ Address::zero(),
                    /* to */ from,
                    U256::zero(), // Zero address always has nonce 0.
                    value,
                    /* data */
                    (tx_hash, U256::from(cross_space_nonce)).abi_encode(),
                ));
                cross_space_nonce += 1;
                // The second phantom transaction for cross-space call, transfer
                // balance and gas fee from the zero address to the mapped
                // sender
                maybe_working_tx = Some(PhantomTransaction {
                    from,
                    nonce,
                    action,
                    value,
                    data,
                    ..Default::default()
                });
            } else if event_sig == &WithdrawEvent::EVENT_SIG {
                let from = Address::from(
                    Bytes20::abi_decode(&log.topics[1].as_ref()).unwrap(),
                );
                let (value, nonce) =
                    ABIDecodable::abi_decode(&log.data).unwrap();
                // The only one transaction for the withdraw
                phantom_txs.push(PhantomTransaction::simple_transfer(
                    from,
                    Address::zero(),
                    nonce,
                    value,
                    /* data */ vec![],
                ));
            } else if event_sig == &ReturnEvent::EVENT_SIG {
                let success: bool =
                    ABIDecodable::abi_decode(&log.data).unwrap();

                let mut working_tx =
                    std::mem::take(&mut maybe_working_tx).unwrap();

                working_tx.outcome_status = if success {
                    TransactionStatus::Success
                } else {
                    TransactionStatus::Failure
                };

                // Complete the second transaction for cross-space call.
                phantom_txs.push(working_tx);
            }
        } else if log.space == Space::Ethereum {
            if let Some(ref mut working_tx) = maybe_working_tx {
                // The receipt is generated in cross-space call
                working_tx.logs.push(log.clone());
                working_tx.log_bloom.accrue_bloom(&log.bloom());
            } else {
                // The receipt is generated in evm-space transaction. Does
                // nothing.
            }
        }
    }
    return phantom_txs;
}
