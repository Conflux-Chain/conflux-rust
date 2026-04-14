mod cfx_filter_handler;
mod cfx_handler;
mod debug_handler;
pub mod helpers;
mod light;
mod pos_handler;
mod pubsub;
mod test_handler;
mod trace_handler;
mod txpool_handler;

pub use cfx_filter_handler::{CfxFilterHandler, UnfinalizedEpochs};
pub use cfx_handler::{check_balance_against_transaction, CfxHandler};
pub use debug_handler::DebugHandler;
pub use pos_handler::{
    convert_to_pos_epoch_reward, hash_value_to_h256, PosHandler,
};
pub use pubsub::PubSubHandler;
pub use test_handler::TestHandler;
pub use trace_handler::TraceHandler;
pub use txpool_handler::TxPoolHandler;

use cfx_types::H256;
use keccak_hash::keccak;

/// Returns a eth_sign-compatible hash of data to sign.
pub fn eth_data_hash(mut data: Vec<u8>) -> H256 {
    let mut message_data =
        format!("\x19Ethereum Signed Message:\n{}", data.len()).into_bytes();
    message_data.append(&mut data);
    keccak(message_data)
}
