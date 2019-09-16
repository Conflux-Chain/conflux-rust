// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate futures;

use cfx_types::{Bloom, H160, H256, KECCAK_EMPTY_BLOOM};
use futures::{future, stream, Future, Stream};
use std::{collections::BTreeSet, sync::Arc};

use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    Account, EpochNumber, Receipt, SignedTransaction, StateRoot,
};

use crate::{
    consensus::ConsensusGraph,
    network::{NetworkContext, NetworkService},
    parameters::{
        consensus::DEFERRED_STATE_EPOCH_COUNT,
        light::{LOG_FILTERING_LOOKAHEAD, MAX_POLL_TIME},
    },
    statedb::StorageKey,
    storage,
    sync::SynchronizationGraph,
};

use super::{
    common::{poll_future, poll_stream, with_timeout, LedgerInfo},
    Error, Handler as LightHandler, LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
};

pub struct QueryService {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

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
        let res: Result<T, Error> =
            self.network.with_context(LIGHT_PROTOCOL_ID, |io| Ok(f(io)));
        res.unwrap()
    }

    fn retrieve_state_root<'a>(
        &'a self, epoch: u64,
    ) -> impl Future<Item = StateRoot, Error = Error> + 'a {
        trace!("retrieve_state_root epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME, /* timeout */
            format!("Timeout while retrieving state root for epoch {}", epoch), /* error */
            self.with_io(|io| self.handler.state_roots.request_now(io, epoch)),
        )
    }

    fn retrieve_state_entry<'a>(
        &'a self, epoch: u64, key: Vec<u8>,
    ) -> impl Future<Item = Option<Vec<u8>>, Error = Error> + 'a {
        trace!("retrieve_state_entry epoch = {}, key = {:?}", epoch, key);

        with_timeout(
            *MAX_POLL_TIME, /* timeout */
            format!("Timeout while retrieving state entry for epoch {} with key {:?}", epoch, key), /* error */
            self.with_io(|io| self.handler.state_entries.request_now(io, epoch, key.clone()))
        )
    }

    fn retrieve_bloom<'a>(
        &'a self, epoch: u64,
    ) -> impl Future<Item = Bloom, Error = Error> + 'a {
        trace!("retrieve_bloom epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME, /* timeout */
            format!("Timeout while retrieving bloom for epoch {}", epoch), /* error */
            self.handler.blooms.request(epoch),
        )
    }

    fn retrieve_receipts<'a>(
        &'a self, epoch: u64,
    ) -> impl Future<Item = Vec<Vec<Receipt>>, Error = Error> + 'a {
        trace!("retrieve_receipts epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME, /* timeout */
            format!("Timeout while retrieving receipts for epoch {}", epoch), /* error */
            self.handler.receipts.request(epoch),
        )
    }

    fn retrieve_block_txs<'a>(
        &'a self, hash: H256,
    ) -> impl Future<Item = Vec<SignedTransaction>, Error = Error> + 'a {
        trace!("retrieve_block_txs hash = {:?}", hash);

        with_timeout(
            *MAX_POLL_TIME, /* timeout */
            format!("Timeout while retrieving block txs for block {}", hash), /* error */
            self.handler.block_txs.request(hash),
        )
    }

    fn account_key(root: &StateRoot, address: H160) -> Vec<u8> {
        let padding = storage::MultiVersionMerklePatriciaTrie::padding(
            &root.snapshot_root,
            &root.intermediate_delta_root,
        );

        StorageKey::new_account_key(&address, &padding)
            .as_ref()
            .to_vec()
    }

    fn code_key(root: &StateRoot, address: H160, code_hash: H256) -> Vec<u8> {
        let padding = storage::MultiVersionMerklePatriciaTrie::padding(
            &root.snapshot_root,
            &root.intermediate_delta_root,
        );

        StorageKey::new_code_key(&address, &code_hash, &padding)
            .as_ref()
            .to_vec()
    }

    fn retrieve_account<'a>(
        &'a self, epoch: u64, address: H160,
    ) -> impl Future<Item = Option<Account>, Error = String> + 'a {
        trace!(
            "retrieve_account epoch = {}, address = {:?}",
            epoch,
            address
        );

        self.retrieve_state_root(epoch)
            .map(move |root| Self::account_key(&root, address))
            .and_then(move |key| self.retrieve_state_entry(epoch, key))
            .and_then(|entry| match entry {
                Some(entry) => Ok(Some(rlp::decode(&entry[..])?)),
                None => Ok(None),
            })
            .map_err(|e| format!("{}", e))
    }

    fn retrieve_code<'a>(
        &'a self, epoch: u64, address: H160, code_hash: H256,
    ) -> impl Future<Item = Option<Vec<u8>>, Error = String> + 'a {
        trace!(
            "retrieve_code epoch = {}, address = {:?}, code_hash = {:?}",
            epoch,
            address,
            code_hash
        );

        self.retrieve_state_root(epoch)
            .map(move |root| Self::code_key(&root, address, code_hash))
            .and_then(move |key| self.retrieve_state_entry(epoch, key))
            .map_err(|e| format!("{}", e))
    }

    pub fn get_account(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<Account>, String> {
        info!("get_account epoch={:?} address={:?}", epoch, address);

        let epoch = match self.get_height_from_epoch_number(epoch) {
            Ok(epoch) => epoch,
            Err(e) => return Err(format!("{}", e)),
        };

        match poll_future(&mut self.retrieve_account(epoch, address)) {
            Ok(account) => Ok(account),
            Err(e) => {
                warn!("Error while retrieving account: {}", e);
                Err(format!("{}", e))
            }
        }
    }

    pub fn get_code(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<Vec<u8>>, String> {
        info!("get_code epoch={:?} address={:?}", epoch, address);

        let epoch = match self.get_height_from_epoch_number(epoch) {
            Ok(epoch) => epoch,
            Err(e) => return Err(format!("{}", e)),
        };

        let mut code = self
            .retrieve_account(epoch, address)
            .and_then(move |acc| match acc {
                Some(acc) => Ok(acc.code_hash),
                None => Err(format!(
                    "Account {:?} (number={:?}) does not exist",
                    address, epoch,
                )),
            })
            .and_then(move |hash| self.retrieve_code(epoch, address, hash));

        match poll_future(&mut code) {
            Ok(code) => Ok(code),
            Err(e) => {
                warn!("Error while retrieving code: {}", e);
                Err(e)
            }
        }
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

    pub fn get_tx(&self, hash: H256) -> Result<SignedTransaction, String> {
        info!("get_tx hash={:?}", hash);

        let mut tx = future::ok(hash).and_then(|hash| {
            trace!("hash = {:?}", hash);

            let tx = self.with_io(|io| self.handler.txs.request_now(io, hash));

            with_timeout(
                *MAX_POLL_TIME,                                  /* timeout */
                format!("Timeout while retrieving tx {}", hash), /* error */
                tx,
            )
        });

        match poll_future(&mut tx) {
            Ok(tx) => Ok(tx),
            Err(e) => {
                warn!("Error while retrieving tx: {}", e);
                Err(format!("{}", e))
            }
        }
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
    ) -> Result<(Vec<u64>, Box<dyn Fn(H256) -> bool>), FilterError> {
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

    pub fn get_logs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        debug!("get_logs filter = {:?}", filter);

        // find epochs and blocks to match against
        let (epochs, block_filter) = self.get_filter_epochs(&filter)?;
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
            .map(|epoch| self.retrieve_bloom(epoch).map(move |bloom| (epoch, bloom)))

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
            .map(|epoch| self.retrieve_receipts(epoch).map(move |receipts| (epoch, receipts)))

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

            .filter(|log| {
                block_filter(log.block_hash)
            })

            // retrieve block txs
            .map(|log| self.retrieve_block_txs(log.block_hash).map(move |txs| (log, txs)))

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
            match poll_stream(&mut stream) {
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
