use cfx_parity_trace_types::TransactionExecTraces;
use cfx_types::{Bloom, U256};
use primitives::{BlockHeader, Receipt, SignedTransaction};
use std::sync::Arc;

pub struct PhantomBlock {
    pub pivot_header: BlockHeader,
    pub transactions: Vec<Arc<SignedTransaction>>,
    pub receipts: Vec<Receipt>,
    pub errors: Vec<String>,
    pub bloom: Bloom,
    pub traces: Vec<TransactionExecTraces>,
    pub total_gas_limit: U256, // real gas limit of the block
}
