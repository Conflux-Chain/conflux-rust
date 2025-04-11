use async_trait::async_trait;
use cfx_rpc_eth_api::TxPoolApiServer;
use cfx_rpc_eth_types::{
    Transaction, TxpoolContent, TxpoolContentFrom, TxpoolInspect,
    TxpoolInspectSummary, TxpoolStatus,
};
use cfx_types::{Address, AddressWithSpace, Space, U256, U64};
use cfxcore::SharedTransactionPool;
use jsonrpsee::core::RpcResult;
use primitives::SignedTransaction;
use std::{collections::BTreeMap, sync::Arc};

pub struct TxPoolApi {
    tx_pool: SharedTransactionPool,
}

impl TxPoolApi {
    pub fn new(tx_pool: SharedTransactionPool) -> Self { Self { tx_pool } }

    fn nonce_map_convert(
        (nonce, tx): (U256, Arc<SignedTransaction>),
    ) -> (String, Transaction) {
        (
            nonce.to_string(),
            Transaction::from_signed(&tx, (None, None, None), (None, None)),
        )
    }
}

#[async_trait]
impl TxPoolApiServer for TxPoolApi {
    async fn txpool_status(&self) -> RpcResult<TxpoolStatus> {
        let pending = self.tx_pool.total_pending(Some(Space::Ethereum));
        let queued = self.tx_pool.total_queued(Some(Space::Ethereum));
        Ok(TxpoolStatus {
            pending: U64::from(pending),
            queued: U64::from(queued),
        })
    }

    async fn txpool_inspect(&self) -> RpcResult<TxpoolInspect> {
        let converter =
            |(addr, nonce_map): (Address, BTreeMap<String, Transaction>)| {
                (
                    addr,
                    nonce_map
                        .into_iter()
                        .map(|(nonce, tx)| {
                            (nonce, TxpoolInspectSummary::from_tx(tx))
                        })
                        .collect(),
                )
            };

        let content = self.txpool_content().await?;
        let pending = content.pending.into_iter().map(converter).collect();
        let queued = content.queued.into_iter().map(converter).collect();
        Ok(TxpoolInspect { pending, queued })
    }

    async fn txpool_content_from(
        &self, from: Address,
    ) -> RpcResult<TxpoolContentFrom> {
        let (pending, queued) =
            self.tx_pool.eth_content_from(AddressWithSpace {
                address: from,
                space: Space::Ethereum,
            });
        let pending =
            pending.into_iter().map(Self::nonce_map_convert).collect();
        let queued = queued.into_iter().map(Self::nonce_map_convert).collect();
        Ok(TxpoolContentFrom { pending, queued })
    }

    async fn txpool_content(&self) -> RpcResult<TxpoolContent> {
        let converter = |(addr, nonce_map): (
            AddressWithSpace,
            BTreeMap<U256, Arc<SignedTransaction>>,
        )| {
            (
                addr.address,
                nonce_map.into_iter().map(Self::nonce_map_convert).collect(),
            )
        };
        let (pending, queued) = self.tx_pool.eth_content(Some(Space::Ethereum));
        let pending = pending.into_iter().map(converter).collect();
        let queued = queued.into_iter().map(converter).collect();
        Ok(TxpoolContent { pending, queued })
    }
}
