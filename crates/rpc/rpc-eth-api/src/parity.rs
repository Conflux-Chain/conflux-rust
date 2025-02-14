use cfx_rpc_eth_types::{BlockNumber as BlockId, Receipt};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server, namespace = "parity")]
pub trait ParityApi {
    /// Returns all transaction receipts for a given block.
    #[method(name = "getBlockReceipts")]
    async fn block_receipts(
        &self, block_id: BlockId,
    ) -> RpcResult<Option<Vec<Receipt>>>;
}
