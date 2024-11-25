use async_trait::async_trait;
use cfx_rpc_eth_api::Web3ApiServer;
use cfx_rpc_primitives::Bytes;
use cfx_types::H256;
use clap::crate_version;
use jsonrpsee::core::RpcResult;
use keccak_hash::keccak;

pub struct Web3Api;

impl Web3Api {
    pub fn new() -> Web3Api { Web3Api }
}

#[async_trait]
impl Web3ApiServer for Web3Api {
    async fn client_version(&self) -> RpcResult<String> {
        Ok(parity_version::version(crate_version!()))
    }

    fn sha3(&self, input: Bytes) -> RpcResult<H256> {
        Ok(keccak(input.into_vec()))
    }
}

impl std::fmt::Debug for Web3Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Web3Api").finish_non_exhaustive()
    }
}
