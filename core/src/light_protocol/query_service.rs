// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{FullPeerFilter, LedgerInfo},
        message::msgid,
        Handler as LightHandler, LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
    },
    network::{NetworkContext, NetworkService},
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{LOG_FILTERING_LOOKAHEAD, MAX_POLL_TIME},
    },
    sync::SynchronizationGraph,
};
use cfx_types::{Bloom, H160, H256, KECCAK_EMPTY_BLOOM};
use futures::{
    future::{self, Either},
    stream, FutureExt, StreamExt, TryFutureExt, TryStreamExt,
};
use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    Account, EpochNumber, Receipt, SignedTransaction, StateRoot, StorageKey,
    TransactionAddress,
};
use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};

type TxInfo = (
    SignedTransaction,
    Receipt,
    TransactionAddress,
    Option<u64>,  /* maybe_epoch */
    Option<H256>, /* maybe_state_root */
);

// As of now, the jsonrpc crate uses legacy futures (futures@0.1 and tokio@0.1).
// Because of this, our RPC runtime cannot handle tokio@0.2 timing primitives.
// As a temporary workaround, we use the old `tokio_timer::Timeout` instead.
async fn with_timeout<T>(
    d: Duration, msg: String, fut: impl Future<Output = T> + Send + Sync,
) -> Result<T, String> {
    // convert `fut` into futures@0.1
    let fut = fut.unit_error().boxed().compat();

    // set timeout
    let with_timeout = tokio_timer::Timeout::new(fut, d);

    // convert back to std::future
    use futures::compat::Future01CompatExt;
    let with_timeout = with_timeout.compat();

    // set error message
    with_timeout.await.map_err(|_| msg)
}

pub struct QueryService {
    // shared consensus graph
    consensus: SharedConsensusGraph,

    // light protocol handler
    handler: Arc<LightHandler>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // shared network service
    network: Arc<NetworkService>,
}

impl QueryService {
    pub fn new(
        consensus: SharedConsensusGraph, graph: Arc<SynchronizationGraph>,
        network: Arc<NetworkService>, throttling_config_file: Option<String>,
    ) -> Self
    {
        let handler = Arc::new(LightHandler::new(
            consensus.clone(),
            graph,
            throttling_config_file,
        ));
        let ledger = LedgerInfo::new(consensus.clone());

        QueryService {
            consensus,
            handler,
            ledger,
            network,
        }
    }

    pub fn register(&self) -> Result<(), String> {
        self.network
            .register_protocol(
                self.handler.clone(),
                LIGHT_PROTOCOL_ID,
                &[LIGHT_PROTOCOL_VERSION],
            )
            .map_err(|e| {
                format!("failed to register protocol QueryService: {:?}", e)
            })
    }

    fn with_io<T>(&self, f: impl FnOnce(&dyn NetworkContext) -> T) -> T {
        self.network
            .with_context(LIGHT_PROTOCOL_ID, |io| f(io))
            .expect("Unable to access network service")
    }

    #[allow(dead_code)]
    async fn retrieve_state_root(
        &self, epoch: u64,
    ) -> Result<StateRoot, String> {
        trace!("retrieve_state_root epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving state root for epoch {}", epoch),
            self.with_io(|io| self.handler.state_roots.request_now(io, epoch)),
        )
        .await
    }

    async fn retrieve_state_entry(
        &self, epoch: u64, key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        trace!("retrieve_state_entry epoch = {}, key = {:?}", epoch, key);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving state entry for epoch {} with key {:?}", epoch, key),
            self.with_io(|io| self.handler.state_entries.request_now(io, epoch, key)),
        )
        .await
    }

    async fn retrieve_bloom(&self, epoch: u64) -> Result<(u64, Bloom), String> {
        trace!("retrieve_bloom epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving bloom for epoch {}", epoch),
            self.handler.blooms.request(epoch),
        )
        .await
        .map(|bloom| (epoch, bloom))
    }

    async fn retrieve_receipts(
        &self, epoch: u64,
    ) -> Result<(u64, Vec<Vec<Receipt>>), String> {
        trace!("retrieve_receipts epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving receipts for epoch {}", epoch),
            self.handler.receipts.request(epoch),
        )
        .await
        .map(|receipts| (epoch, receipts))
    }

    async fn retrieve_block_txs(
        &self, log: LocalizedLogEntry,
    ) -> Result<(LocalizedLogEntry, Vec<SignedTransaction>), String> {
        trace!("retrieve_block_txs log = {:?}", log);
        let hash = log.block_hash;

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving block txs for block {}", hash),
            self.handler.block_txs.request(hash),
        )
        .await
        .map(|block_txs| (log, block_txs))
    }

    async fn retrieve_tx_info(
        &self, hash: H256,
    ) -> Result<(SignedTransaction, Receipt, TransactionAddress), String> {
        trace!("retrieve_tx_info hash = {:?}", hash);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving tx info for tx {}", hash),
            self.with_io(|io| self.handler.tx_infos.request_now(io, hash)),
        )
        .await
    }

    fn account_key(address: &H160) -> Vec<u8> {
        StorageKey::AccountKey(&address.0).to_key_bytes()
    }

    fn code_key(address: &H160, code_hash: &H256) -> Vec<u8> {
        StorageKey::CodeKey {
            address_bytes: &address.0,
            code_hash_bytes: &code_hash.0,
        }
        .to_key_bytes()
    }

    async fn retrieve_account(
        &self, epoch: u64, address: H160,
    ) -> Result<Option<Account>, String> {
        trace!(
            "retrieve_account epoch = {}, address = {:?}",
            epoch,
            address
        );

        // trigger state root request but don't wait for result
        // FIXME: is there a better way?
        let _ =
            self.with_io(|io| self.handler.state_roots.request_now(io, epoch));

        let key = Self::account_key(&address);

        let entry = match self.retrieve_state_entry(epoch, key).await? {
            None => return Ok(None),
            Some(entry) => entry,
        };

        let account = rlp::decode(&entry[..]).map_err(|e| format!("{}", e))?;
        Ok(Some(account))
    }

    async fn retrieve_code(
        &self, epoch: u64, address: H160, code_hash: H256,
    ) -> Result<Option<Vec<u8>>, String> {
        trace!(
            "retrieve_code epoch = {}, address = {:?}, code_hash = {:?}",
            epoch,
            address,
            code_hash
        );

        let key = Self::code_key(&address, &code_hash);
        self.retrieve_state_entry(epoch, key).await
    }

    pub async fn get_account(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<Account>, String> {
        info!("get_account epoch={:?} address={:?}", epoch, address);

        let epoch = match self.get_height_from_epoch_number(epoch) {
            Ok(epoch) => epoch,
            Err(e) => return Err(format!("{}", e)),
        };

        self.retrieve_account(epoch, address).await
    }

    pub async fn get_code(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<Vec<u8>>, String> {
        info!("get_code epoch={:?} address={:?}", epoch, address);

        let epoch = match self.get_height_from_epoch_number(epoch) {
            Ok(epoch) => epoch,
            Err(e) => return Err(format!("{}", e)),
        };

        let account = self
            .retrieve_account(epoch, address)
            .await
            .map_err(|e| format!("Unable to retrieve account: {:?}", e))?;

        let code_hash = match account {
            Some(account) => account.code_hash,
            None => {
                return Err(format!(
                    "Account {:?} (number={:?}) does not exist",
                    address, epoch,
                ))
            }
        };

        self.retrieve_code(epoch, address, code_hash).await
    }

    pub async fn get_tx_info(&self, hash: H256) -> Result<TxInfo, String> {
        info!("get_tx_info hash={:?}", hash);

        // Note: if a transaction does not exist, we fail with timeout, as
        //       peers cannot provide non-existence proofs for transactions.
        // FIXME: is there a better way?
        let (tx, receipt, address) = self.retrieve_tx_info(hash).await?;

        let hash = address.block_hash;
        let epoch = self.consensus.get_block_epoch_number(&hash);

        let root = epoch
            .and_then(|e| self.handler.witnesses.root_hashes_of(e))
            .map(|(state_root, _, _)| state_root);

        Ok((tx, receipt, address, epoch, root))
    }

    /// Relay raw transaction to all peers.
    // TODO(thegaram): consider returning TxStatus instead of bool,
    // e.g. Failed, Sent/Pending, Confirmed, etc.
    pub fn send_raw_tx(&self, raw: Vec<u8>) -> bool {
        debug!("send_raw_tx raw={:?}", raw);

        let mut success = false;

        let peers = FullPeerFilter::new(msgid::SEND_RAW_TX)
            .select_all(self.handler.peers.clone());

        for peer in peers {
            // relay to peer
            let res = self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
                self.handler.send_raw_tx(io, peer, raw.clone())
            });

            // check error
            match res {
                Err(e) => warn!("Failed to relay to peer={:?}: {:?}", peer, e),
                Ok(_) => {
                    debug!("Tx relay to peer {:?} successful", peer);
                    success = true;
                }
            }
        }

        success
    }

    pub async fn get_tx(
        &self, hash: H256,
    ) -> Result<SignedTransaction, String> {
        info!("get_tx hash={:?}", hash);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving transaction with hash {}", hash),
            self.with_io(|io| self.handler.txs.request_now(io, hash)),
        )
        .await
    }

    /// Apply filter to all logs within a receipt.
    /// NOTE: `log.transaction_hash` is not known at this point,
    /// so this field has to be filled later on.
    fn filter_receipt_logs(
        epoch: u64, block_hash: H256, transaction_index: usize,
        num_logs_remaining: &mut usize, mut logs: Vec<LogEntry>,
        filter: Filter,
    ) -> impl Iterator<Item = LocalizedLogEntry>
    {
        let num_logs = logs.len();

        let log_base_index = *num_logs_remaining;
        *num_logs_remaining -= num_logs;

        // process logs in reverse order
        logs.reverse();

        logs.into_iter()
            .enumerate()
            .filter(move |(_, entry)| filter.matches(&entry))
            .map(move |(ii, entry)| LocalizedLogEntry {
                block_hash,
                epoch_number: epoch,
                entry,
                log_index: log_base_index - ii - 1,
                transaction_hash: KECCAK_EMPTY_BLOOM, // will fill in later
                transaction_index,
                transaction_log_index: num_logs - ii - 1,
            })
    }

    /// Apply filter to all receipts within a block.
    fn filter_block_receipts(
        epoch: u64, hash: H256, mut receipts: Vec<Receipt>, filter: Filter,
    ) -> impl Iterator<Item = LocalizedLogEntry> {
        // number of receipts in this block
        let num_receipts = receipts.len();

        // number of logs in this block
        let mut remaining = receipts.iter().fold(0, |s, r| s + r.logs.len());

        // process block receipts in reverse order
        receipts.reverse();

        receipts.into_iter().map(|r| r.logs).enumerate().flat_map(
            move |(ii, logs)| {
                debug!("block_hash {:?} logs = {:?}", hash, logs);
                Self::filter_receipt_logs(
                    epoch,
                    hash,
                    num_receipts - ii - 1,
                    &mut remaining,
                    logs,
                    filter.clone(),
                )
            },
        )
    }

    /// Apply filter to all receipts within an epoch.
    fn filter_epoch_receipts(
        &self, epoch: u64, mut receipts: Vec<Vec<Receipt>>, filter: Filter,
    ) -> Result<impl Iterator<Item = LocalizedLogEntry>, String> {
        // get epoch blocks in execution order
        let mut hashes = self
            .ledger
            .block_hashes_in(epoch)
            .map_err(|e| format!("{}", e))?;

        // process epoch receipts in reverse order
        receipts.reverse();
        hashes.reverse();

        let matching = receipts.into_iter().zip(hashes).flat_map(
            move |(receipts, hash)| {
                trace!("block_hash {:?} receipts = {:?}", hash, receipts);
                Self::filter_block_receipts(
                    epoch,
                    hash,
                    receipts,
                    filter.clone(),
                )
            },
        );

        Ok(matching)
    }

    fn get_height_from_epoch_number(
        &self, epoch: EpochNumber,
    ) -> Result<u64, FilterError> {
        // find highest epoch that we are able to verify based on witness info
        let latest_verified = self.handler.witnesses.latest_verified();

        let latest_verifiable = match latest_verified {
            n if n >= DEFERRED_STATE_EPOCH_COUNT => {
                n - DEFERRED_STATE_EPOCH_COUNT
            }
            _ => {
                return Err(FilterError::UnableToVerify {
                    epoch: 0,
                    latest_verifiable: 0,
                })
            }
        };

        trace!(
            "get_height_from_epoch_number epoch = {:?}, latest_verifiable = {}",
            epoch,
            latest_verifiable
        );

        match epoch {
            EpochNumber::Earliest => Ok(0),
            EpochNumber::LatestMined => Ok(latest_verifiable),
            EpochNumber::LatestState => Ok(latest_verifiable),
            EpochNumber::Number(n) if n <= latest_verifiable => Ok(n),
            EpochNumber::Number(n) => Err(FilterError::UnableToVerify {
                epoch: n,
                latest_verifiable,
            }),
        }
    }

    fn get_filter_epochs(
        &self, filter: &Filter,
    ) -> Result<(Vec<u64>, Box<dyn Fn(H256) -> bool + Send + Sync>), FilterError>
    {
        match &filter.block_hashes {
            None => {
                let from_epoch = self
                    .get_height_from_epoch_number(filter.from_epoch.clone())?;
                let to_epoch =
                    self.get_height_from_epoch_number(filter.to_epoch.clone())?;

                if from_epoch > to_epoch {
                    return Err(FilterError::InvalidEpochNumber {
                        from_epoch,
                        to_epoch,
                    });
                }

                let epochs = (from_epoch..(to_epoch + 1)).rev().collect();
                let block_filter = Box::new(|_| true);

                Ok((epochs, block_filter))
            }
            Some(hashes) => {
                // we use BTreeSet to make lookup efficient
                let hashes: BTreeSet<_> = hashes.iter().cloned().collect();

                // we use BTreeSet to ensure order and uniqueness
                let mut epochs = BTreeSet::new();

                for hash in &hashes {
                    match self.consensus.get_block_epoch_number(&hash) {
                        Some(epoch) => epochs.insert(epoch),
                        None => {
                            return Err(FilterError::UnknownBlock {
                                hash: *hash,
                            })
                        }
                    };
                }

                let epochs = epochs.into_iter().rev().collect();
                let block_filter = Box::new(move |hash| hashes.contains(&hash));

                Ok((epochs, block_filter))
            }
        }
    }

    pub async fn get_logs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, String> {
        debug!("get_logs filter = {:?}", filter);

        // find epochs and blocks to match against
        let (epochs, block_filter) = self
            .get_filter_epochs(&filter)
            .map_err(|e| format!("{}", e))?;

        debug!("Executing filter on epochs {:?}", epochs);

        // construct blooms for matching epochs
        let blooms = filter.bloom_possibilities();

        // The returned future will outlive this method (`get_logs`). Thus, we
        // need to move `blooms` into `bloom_match` and `bloom_match` into the
        // future.
        let bloom_match = move |block_log_bloom: &Bloom| {
            blooms
                .iter()
                .any(|bloom| block_log_bloom.contains_bloom(bloom))
        };

        // set maximum to number of logs returned
        let limit = filter.limit.unwrap_or(::std::usize::MAX);

        // construct a stream object for log filtering
        // we first retrieve the epoch blooms and try to match against them. for
        // matching epochs, we retrieve the corresponding receipts and find the
        // matching entries. finally, for each matching entry, we retrieve the
        // block transactions so that we can add the tx hash. each of these is
        // verified in the corresponding sync handler.

        // NOTE: in the type annotations below, we use these conventions:
        //    Stream<T> = futures::stream::Stream<Item = T>
        // TryStream<T> = futures::stream::TryStream<Ok = T, Error = String>
        // TryFuture<T> = futures::future::TryFuture<Ok = T, Error = String>
        let stream =
            // process epochs one by one
            stream::iter(epochs)
            // --> Stream<u64>

            // retrieve blooms
            .map(|epoch| self.retrieve_bloom(epoch))
            // --> Stream<TryFuture<(u64, Bloom)>>

            .buffered(LOG_FILTERING_LOOKAHEAD)
            // --> TryStream<(u64, Bloom)>

            // find the epochs that match
            .try_filter_map(move |(epoch, bloom)| {
                debug!("Matching epoch {:?} bloom = {:?}", epoch, bloom);

                match bloom_match(&bloom) {
                    true => future::ready(Ok(Some(epoch))),
                    false => future::ready(Ok(None)),
                }
            })
            // --> TryStream<u64>

            // retrieve receipts
            .map(|res| match res {
                Err(e) => Either::Left(future::err(e)),
                Ok(epoch) => Either::Right(self.retrieve_receipts(epoch)),
            })
            // --> Stream<TryFuture<(u64, Vec<Vec<Receipt>>)>>

            .buffered(LOG_FILTERING_LOOKAHEAD)
            // --> TryStream<(u64, Vec<Vec<Receipt>>)>

            // filter logs in epoch
            .map(|res| match res {
                Err(e) => Err(e),
                Ok((epoch, receipts)) => {
                    debug!("Filtering epoch {:?} receipts = {:?}", epoch, receipts);

                    let logs = self
                        .filter_epoch_receipts(epoch, receipts, filter.clone())?
                        .map(|log| Ok(log));

                    Ok(stream::iter(logs))
                }
            })
            // --> TryStream<TryStream<LocalizedLogEntry>>

            .try_flatten()
            // --> TryStream<LocalizedLogEntry>

            // apply block filter
            .try_filter(move |log| future::ready(block_filter(log.block_hash)))
            // --> TryStream<LocalizedLogEntry>

            // retrieve block txs
            .map(|res| match res {
                Err(e) => Either::Left(future::err(e)),
                Ok(log) => Either::Right(self.retrieve_block_txs(log)),
            })
            // --> Stream<TryFuture<(LocalizedLogEntry, Vec<SignedTransaction>)>>

            .buffered(LOG_FILTERING_LOOKAHEAD)
            // --> TryStream<(LocalizedLogEntry, Vec<SignedTransaction>)>

            .map_ok(|(mut log, txs)| {
                debug!("processing log = {:?} txs = {:?}", log, txs);

                // at this point, we're trying to retrieve a block tx based on verified
                // bloom, receipt, and tx information. if all the verifications passed
                // before, then we must have the corresponding tx in this block.
                assert!(log.transaction_index < txs.len());

                // set tx hash
                log.transaction_hash = txs[log.transaction_index].hash();
                log
            })
            // --> TryStream<LocalizedLogEntry>

            // limit number of entries we need
            .take(limit)
            // --> TryStream<LocalizedLogEntry>

            .try_collect();
        // --> TryFuture<Vec<LocalizedLogEntry>>

        let mut matching: Vec<_> = stream.await?;
        matching.reverse();
        debug!("Collected matching logs = {:?}", matching);
        Ok(matching)
    }
}
