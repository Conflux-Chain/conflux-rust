use cfx_rpc_primitives::Bytes;
use cfx_types::H256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Web3 rpc interface.
#[rpc(server, namespace = "web3")]
pub trait Web3Api {
    /// Returns current client version.
    #[method(name = "clientVersion")]
    async fn client_version(&self) -> RpcResult<String>;

    /// Returns sha3 of the given data.
    #[method(name = "sha3")]
    fn sha3(&self, input: Bytes) -> RpcResult<H256>;
}
