// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use cfx_types::{Bloom, H160, H256, KECCAK_EMPTY_BLOOM};
use futures::{future, stream, Future, Stream};
use std::{sync::Arc, time::Duration};

use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    Account, EpochNumber, Receipt, SignedTransaction, StateRoot,
};

use crate::{
    consensus::ConsensusGraph,
    network::{NetworkService, PeerId},
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{LOG_FILTERING_LOOKAHEAD, MAX_POLL_TIME_MS},
    },
    statedb::StorageKey,
    storage,
    sync::SynchronizationGraph,
};

use super::{
    common::{poll_next, with_timeout, LedgerInfo},
    handler::QueryResult,
    message::{GetStateEntry, GetStateRoot, GetTxs},
    Error, ErrorKind, Handler as LightHandler, LIGHT_PROTOCOL_ID,
    LIGHT_PROTOCOL_VERSION,
};

pub struct QueryService {
    // light protocol handler
    handler: Arc<LightHandler>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // shared network service
    network: Arc<NetworkService>,
}

impl QueryService {
    pub fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
        network: Arc<NetworkService>,
    ) -> Self
    {
        let handler = Arc::new(LightHandler::new(consensus.clone(), graph));
        let ledger = LedgerInfo::new(consensus.clone());

        QueryService {
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

    pub fn query_state_root(
        &self, peer: PeerId, epoch: u64,
    ) -> Result<StateRoot, Error> {
        // TODO(thegaram): retrieve from cache
        info!("query_state_root epoch={:?}", epoch);

        let req = GetStateRoot {
            request_id: 0,
            epoch,
        };

        self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
            match self.handler.query.execute(io, peer, req)? {
                QueryResult::StateRoot(sr) => Ok(sr),
                _ => Err(ErrorKind::UnexpectedResponse.into()),
            }
        })
    }

    pub fn query_state_entry(
        &self, peer: PeerId, epoch: u64, key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Error> {
        info!("query_state_entry epoch={:?} key={:?}", epoch, key);

        let req = GetStateEntry {
            request_id: 0,
            epoch,
            key,
        };

        self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
            match self.handler.query.execute(io, peer, req)? {
                QueryResult::StateEntry(entry) => Ok(entry),
                _ => Err(ErrorKind::UnexpectedResponse.into()),
            }
        })
    }

    pub fn query_account(
        &self, peer: PeerId, epoch: u64, address: H160,
    ) -> Result<Option<Account>, Error> {
        info!(
            "query_account peer={:?} epoch={:?} address={:?}",
            peer, epoch, address
        );

        // retrieve state root from peer
        let state_root = self.query_state_root(peer, epoch)?;

        // calculate corresponding state trie key
        let key = {
            let padding = storage::MultiVersionMerklePatriciaTrie::padding(
                &state_root.snapshot_root,
                &state_root.intermediate_delta_root,
            );

            StorageKey::new_account_key(&address, &padding)
                .as_ref()
                .to_vec()
        };

        // retrieve state entry from peer
        let entry = self.query_state_entry(peer, epoch, key)?;

        let account = match entry {
            None => None,
            Some(entry) => Some(rlp::decode(&entry[..])?),
        };

        Ok(account)
    }

    pub fn get_account(&self, epoch: u64, address: H160) -> Option<Account> {
        info!("get_account epoch={:?} address={:?}", epoch, address);

        // try each peer until we succeed
        // TODO(thegaram): only query peers who already have `epoch`
        for peer in self.handler.peers.all_peers_shuffled() {
            match self.query_account(peer, epoch, address) {
                Ok(account) => return account,
                Err(e) => {
                    warn!(
                        "Failed to get account from peer={:?}: {:?}",
                        peer, e
                    );
                }
            };
        }

        None
    }

    /// Relay raw transaction to all peers.
    // TODO(thegaram): consider returning TxStatus instead of bool,
    // e.g. Failed, Sent/Pending, Confirmed, etc.
    pub fn send_raw_tx(&self, raw: Vec<u8>) -> bool {
        debug!("send_raw_tx raw={:?}", raw);

        let mut success = false;

        for peer in self.handler.peers.all_peers_shuffled() {
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

    pub fn query_txs(
        &self, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<Vec<SignedTransaction>, Error> {
        info!("query_txs peer={:?} hashes={:?}", peer, hashes);

        let req = GetTxs {
            request_id: 0,
            hashes,
        };

        self.network.with_context(LIGHT_PROTOCOL_ID, |io| {
            match self.handler.query.execute(io, peer, req)? {
                QueryResult::Txs(txs) => Ok(txs),
                _ => Err(ErrorKind::UnexpectedResponse.into()),
            }
        })
    }

    pub fn get_tx(&self, hash: H256) -> Option<SignedTransaction> {
        info!("get_tx hash={:?}", hash);

        // try each peer until we succeed
        for peer in self.handler.peers.all_peers_shuffled() {
            match self.query_txs(peer, vec![hash]) {
                Err(e) => {
                    warn!("Failed to get txs from peer={:?}: {:?}", peer, e);
                }
                Ok(txs) => {
                    match txs.iter().find(|tx| tx.hash() == hash).cloned() {
                        Some(tx) => return Some(tx),
                        None => {
                            warn!(
                                "Peer {} returned {:?}, target tx not found!",
                                peer, txs
                            );
                        }
                    }
                }
            };
        }

        None
    }

    /// Apply filter to all logs within a receipt.
    /// NOTE: `log.transaction_hash` is not known at this point,
    /// so this field has to be filled later on.
    fn filter_receipt_logs(
        block_hash: H256, transaction_index: usize,
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
                block_number: 0, // TODO
                entry,
                log_index: log_base_index - ii - 1,
                transaction_hash: KECCAK_EMPTY_BLOOM, // will fill in later
                transaction_index,
                transaction_log_index: num_logs - ii - 1,
            })
    }

    /// Apply filter to all receipts within a block.
    fn filter_block_receipts(
        hash: H256, mut receipts: Vec<Receipt>, filter: Filter,
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
    ) -> Result<impl Iterator<Item = LocalizedLogEntry>, Error> {
        // get epoch blocks in execution order
        let mut hashes: Vec<H256> = self.ledger.block_hashes_in(epoch)?;

        // process epoch receipts in reverse order
        receipts.reverse();
        hashes.reverse();

        let matching = receipts.into_iter().zip(hashes).flat_map(
            move |(receipts, hash)| {
                trace!("block_hash {:?} receipts = {:?}", hash, receipts);
                Self::filter_block_receipts(hash, receipts, filter.clone())
            },
        );

        Ok(matching)
    }

    fn get_height_from_epoch_number(
        &self, epoch: EpochNumber,
    ) -> Result<u64, FilterError> {
        // find highest epoch that we are able to verify based on witness info
        let latest_verified = self.handler.sync.witnesses.latest_verified();

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

    pub fn get_logs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        debug!("get_logs filter = {:?}", filter);

        // find epochs to match against
        let from_epoch =
            self.get_height_from_epoch_number(filter.from_epoch.clone())?;
        let to_epoch =
            self.get_height_from_epoch_number(filter.to_epoch.clone())?;

        if from_epoch > to_epoch {
            return Err(FilterError::InvalidEpochNumber {
                from_epoch,
                to_epoch,
            });
        }

        let mut epochs: Vec<u64> = (from_epoch..(to_epoch + 1)).collect();
        epochs.reverse();
        debug!("Executing filter on epochs {:?}", epochs);

        // construct blooms for matching epochs
        let blooms = filter.bloom_possibilities();
        let bloom_match = |block_log_bloom: &Bloom| {
            blooms
                .iter()
                .any(|bloom| block_log_bloom.contains_bloom(bloom))
        };

        // set maximum to number of logs returned
        let limit = filter.limit.unwrap_or(::std::usize::MAX) as u64;

        // TODO(thegaram): add support for filter.block_hashes

        // construct a stream object for log filtering
        // we first retrieve the epoch blooms and try to match against them. for
        // matching epochs, we retrieve the corresponding receipts and find the
        // matching entries. finally, for each matching entry, we retrieve the
        // block transactions so that we can add the tx hash. each of these is
        // verified in the corresponding sync handler.
        let mut stream =
            // process epochs one by one
            stream::iter_ok::<_, Error>(epochs)

            // retrieve blooms
            .map(|epoch| {
                debug!("Requesting blooms for {:?}", epoch);

                with_timeout(
                    Duration::from_millis(MAX_POLL_TIME_MS), /* timeout */
                    format!("Timeout while retrieving bloom for epoch {}", epoch), /* error */
                    self.handler.sync.blooms.request(epoch)
                ).map(move |bloom| (epoch, bloom))
            })

            // we first request blooms for up to `LOG_FILTERING_LOOKAHEAD`
            // epochs and then wait for them and process them one by one
            // NOTE: we wrap our future in a future because we don't want to wait for the actual value yet
            .map(future::ok)
            .buffered(LOG_FILTERING_LOOKAHEAD)
            .and_then(|x| x)

            // find the epochs that match
            .filter_map(|(epoch, bloom)| {
                    debug!("Matching epoch {:?} bloom = {:?}", epoch, bloom);

                    match bloom_match(&bloom) {
                        true => Some(epoch),
                        false => None,
                    }
                },
            )

            // retrieve receipts
            .map(|epoch| {
                debug!("Requesting receipts for {:?}", epoch);

                with_timeout(
                    Duration::from_millis(MAX_POLL_TIME_MS), /* timeout */
                    format!("Timeout while retrieving receipts for epoch {}", epoch), /* error */
                    self.handler.sync.receipts.request(epoch)
                ).map(move |receipts| (epoch, receipts))
            })

            // we first request receipts for up to `LOG_FILTERING_LOOKAHEAD`
            // epochs and then wait for them and process them one by one
            .map(future::ok)
            .buffered(LOG_FILTERING_LOOKAHEAD)
            .and_then(|x| x)

            // filter logs in epoch
            .and_then(|(epoch, receipts)| {
                debug!("Filtering epoch {:?} receipts = {:?}", epoch, receipts);
                let logs = self.filter_epoch_receipts(epoch, receipts, filter.clone())?;
                Ok(stream::iter_ok(logs))
            })

            // Stream<Stream<Log>> -> Stream<Log>
            .flatten()

            // retrieve block txs
            .map(|log| {
                debug!("Requesting block txs for {:?}", log.block_hash);

                with_timeout(
                    Duration::from_millis(MAX_POLL_TIME_MS), /* timeout */
                    format!("Timeout while retrieving block txs for block {}", log.block_hash), /* error */
                    self.handler.sync.block_txs.request(log.block_hash)
                ).map(move |txs| (log, txs))
            })

            // we first request txs for up to `LOG_FILTERING_LOOKAHEAD`
            // blocks and then wait for them and process them one by one
            .map(future::ok)
            .buffered(LOG_FILTERING_LOOKAHEAD)
            .and_then(|x| x)

            .map(|(mut log, txs)| {
                debug!("processing log = {:?} txs = {:?}", log, txs);

                // at this point, we're trying to retrieve a block tx based on verified
                // bloom, receipt, and tx information. if all the verifications passed
                // before, then we must have the corresponding tx in this block.
                assert!(log.transaction_index < txs.len());

                // set tx hash
                log.transaction_hash = txs[log.transaction_index].hash();
                log
            })

            // limit number of entries we need
            .take(limit);

        // NOTE: eventually, we might want to extend our RPC with futures and
        // return the async stream directly. for now, we're offering a sync API
        // based on polling.
        // TODO(thegaram): review this
        let mut matching = vec![];

        loop {
            // NOTE: poll_next will poll indefinitely; the provided stream must
            // make sure it terminates eventually.
            match poll_next(&mut stream) {
                Ok(None) => break,
                Ok(Some(x)) => matching.push(x),
                Err(e) => return Err(FilterError::Custom(format!("{}", e))),
            }
        }

        matching.reverse();
        debug!("Collected matching logs = {:?}", matching);
        Ok(matching)
    }
}
