use crate::hash::keccak;
use cfx_parameters::internal_contract_addresses::SYSTEM_EVENT_ADDRESS;
use cfx_types::{Address, H256, U256};
use primitives::LogEntry;
use solidity_abi::{IndexedArg, NonIndexedArgs};

lazy_static! {
    pub static ref MESSAGE_CALL_TRANSFER_SIG: H256 =
        keccak("MessageCallTransfer(address,address,u256)");
}

pub fn log_message_call_transfer(
    sender: &Address, receiver: &Address, val: &U256,
) -> LogEntry {
    LogEntry {
        address: SYSTEM_EVENT_ADDRESS.clone(),
        topics: vec![
            MESSAGE_CALL_TRANSFER_SIG.clone(),
            sender.to_indexed_arg(),
            receiver.to_indexed_arg(),
        ],
        data: val.to_non_indexed_args(),
    }
}
