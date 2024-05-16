use cfx_types::H256;
use primitives::TransactionWithSignature;

/// Messages to broadcast via chain
#[allow(dead_code)]
pub enum ChainMessageType {
    /// Consensus message
    Consensus(Vec<u8>),
    /// Message with private transaction
    PrivateTransaction(H256, Vec<u8>),
    /// Message with signed private transaction
    SignedPrivateTransaction(H256, Vec<u8>),
}

/// Used by `ChainNotify` `new_blocks()`
#[allow(dead_code)]
pub struct NewBlocks {}

impl NewBlocks {
    /// Constructor
    #[allow(dead_code)]
    pub fn new() -> NewBlocks { NewBlocks {} }
}

pub trait ChainNotify: Send + Sync {
    /// fires when chain has new blocks.
    fn new_blocks(&self, _new_blocks: NewBlocks) {
        // does nothing by default
    }

    /// fires when chain achieves active mode
    fn start(&self) {
        // does nothing by default
    }

    /// fires when chain achieves passive mode
    fn stop(&self) {
        // does nothing by default
    }

    /// fires when chain broadcasts a message
    fn broadcast(&self, _message_type: ChainMessageType) {
        // does nothing by default
    }

    /// fires when new transactions are received from a peer
    fn transactions_received(
        &self, _txs: &[TransactionWithSignature], _peer_id: usize,
    ) {
        // does nothing by default
    }
}
