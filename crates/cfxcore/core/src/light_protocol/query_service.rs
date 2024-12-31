// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::SharedConsensusGraph,
    errors::{account_result_to_rpc_result, Error},
    light_protocol::{
        common::{FullPeerFilter, LedgerInfo},
        handler::sync::TxInfoValidated,
        message::msgid,
        Error as LightError, Handler as LightHandler, LightNodeConfiguration,
        LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
    },
    sync::SynchronizationGraph,
    ConsensusGraph, Notifications,
};
use cfx_addr::Network;
use cfx_executor::state::COMMISSION_PRIVILEGE_SPECIAL_KEY;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    internal_contract_addresses::SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
    light::{
        GAS_PRICE_BATCH_SIZE, GAS_PRICE_BLOCK_SAMPLE_SIZE,
        GAS_PRICE_TRANSACTION_SAMPLE_SIZE, LOG_FILTERING_LOOKAHEAD,
        MAX_POLL_TIME, TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_LOW,
        TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_MEDIUM,
    },
};
use cfx_statedb::global_params::{self, GlobalParamKey};
use cfx_types::{
    address_util::AddressUtil, AllChainID, BigEndianHash, Bloom, H160, H256,
    KECCAK_EMPTY_BLOOM, U256,
};
use futures::{
    future::{self, Either},
    stream, try_join, StreamExt, TryStreamExt,
};
use network::{service::ProtocolVersion, NetworkContext, NetworkService};
use primitives::{
    filter::{FilterError, LogFilter},
    log_entry::{LocalizedLogEntry, LogEntry},
    Account, Block, BlockReceipts, CodeInfo, DepositList, EpochNumber, Receipt,
    SignedTransaction, StorageKey, StorageRoot, StorageValue, TransactionIndex,
    VoteStakeList,
};
use rlp::Rlp;
use std::{collections::BTreeSet, future::Future, sync::Arc, time::Duration};
use tokio::time::timeout;

pub struct TxInfo {
    pub tx: SignedTransaction,
    pub maybe_block_number: Option<u64>,
    pub receipt: Receipt,
    pub tx_index: TransactionIndex,
    pub maybe_epoch: Option<u64>,
    pub maybe_state_root: Option<H256>,
    pub prior_gas_used: U256,
}

async fn with_timeout<T>(
    d: Duration, msg: String,
    fut: impl Future<Output = Result<T, LightError>> + Send + Sync,
) -> Result<T, LightError> {
    let with_timeout = timeout(d, fut);
    // set error message
    with_timeout
        .await
        .map_err(|_| LightError::from(LightError::Timeout(msg)))?
}

pub struct QueryService {
    protocol_version: ProtocolVersion,

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
        notifications: Arc<Notifications>, config: LightNodeConfiguration,
    ) -> Self {
        let handler = Arc::new(LightHandler::new(
            consensus.clone(),
            graph,
            throttling_config_file,
            notifications,
            config,
        ));
        let ledger = LedgerInfo::new(consensus.clone());

        QueryService {
            protocol_version: LIGHT_PROTOCOL_VERSION,
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
                self.protocol_version,
            )
            .map_err(|e| {
                format!("failed to register protocol QueryService: {:?}", e)
            })
    }

    fn with_io<T>(&self, f: impl FnOnce(&dyn NetworkContext) -> T) -> T {
        self.network
            .with_context(self.handler.clone(), LIGHT_PROTOCOL_ID, |io| f(io))
            .expect("Unable to access network service")
    }

    async fn retrieve_state_entry_raw(
        &self, epoch: u64, key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, LightError> {
        trace!(
            "retrieve_state_entry_raw epoch = {}, key = {:?}",
            epoch,
            key
        );

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving state entry for epoch {:?} with key {:?}", epoch, key),
            self.with_io(|io| self.handler.state_entries.request_now(io, epoch, key)),
        )
        .await
    }

    async fn retrieve_state_entry<T: rlp::Decodable>(
        &self, epoch: u64, key: Vec<u8>,
    ) -> Result<Option<T>, LightError> {
        match self.retrieve_state_entry_raw(epoch, key).await? {
            None => Ok(None),
            Some(raw) => {
                let decoded = rlp::decode::<T>(raw.as_ref())
                    .map_err(|e| format!("{}", e))?;
                Ok(Some(decoded))
            }
        }
    }

    async fn retrieve_storage_root(
        &self, epoch: u64, address: H160,
    ) -> Result<StorageRoot, LightError> {
        trace!(
            "retrieve_storage_root epoch = {}, address = {}",
            epoch,
            address
        );

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving storage root for address {:?} in epoch {:?}", address, epoch),
            self.with_io(|io| self.handler.storage_roots.request_now(io, epoch, address)),
        )
        .await
    }

    async fn retrieve_bloom(
        &self, epoch: u64,
    ) -> Result<(u64, Bloom), LightError> {
        trace!("retrieve_bloom epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving bloom for epoch {:?}", epoch),
            self.handler.blooms.request(epoch),
        )
        .await
        .map(|bloom| (epoch, bloom))
    }

    async fn retrieve_receipts(
        &self, epoch: u64,
    ) -> Result<(u64, Vec<BlockReceipts>), LightError> {
        trace!("retrieve_receipts epoch = {}", epoch);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving receipts for epoch {:?}", epoch),
            self.handler.receipts.request(epoch),
        )
        .await
        .map(|receipts| (epoch, receipts))
    }

    pub async fn retrieve_block_txs(
        &self, hash: H256,
    ) -> Result<Vec<SignedTransaction>, LightError> {
        trace!("retrieve_block_txs hash = {:?}", hash);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving block txs for block {:?}", hash),
            self.handler.block_txs.request(hash),
        )
        .await
    }

    async fn retrieve_block_txs_for_log(
        &self, log: LocalizedLogEntry,
    ) -> Result<(LocalizedLogEntry, Vec<SignedTransaction>), LightError> {
        trace!("retrieve_block_txs_for_log log = {:?}", log);

        self.retrieve_block_txs(log.block_hash)
            .await
            .map(|block_txs| (log, block_txs))
    }

    pub async fn retrieve_block(
        &self, hash: H256,
    ) -> Result<Option<Block>, LightError> {
        let genesis = self.consensus.get_data_manager().true_genesis.clone();

        if hash == genesis.hash() {
            return Ok(Some((*genesis).clone()));
        }

        let maybe_block_header = self
            .consensus
            .get_data_manager()
            .block_header_by_hash(&hash);

        let block_header = match maybe_block_header {
            None => return Ok(None),
            Some(h) => (*h).clone(),
        };

        let transactions = self
            .retrieve_block_txs(hash)
            .await?
            .into_iter()
            .map(Arc::new)
            .collect();

        Ok(Some(Block::new(block_header, transactions)))
    }

    async fn retrieve_tx_info(
        &self, hash: H256,
    ) -> Result<TxInfoValidated, LightError> {
        trace!("retrieve_tx_info hash = {:?}", hash);

        with_timeout(
            *MAX_POLL_TIME,
            format!("Timeout while retrieving tx info for tx {:?}", hash),
            self.with_io(|io| self.handler.tx_infos.request_now(io, hash)),
        )
        .await
    }

    pub async fn gas_price(&self) -> Result<Option<U256>, LightError> {
        // collect block hashes for gas price sample
        let mut epoch = self.consensus.best_epoch_number();
        let mut hashes = vec![];
        let mut total_transaction_count_in_processed_blocks = 0;
        let mut processed_block_count = 0;

        let inner = self
            .consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
            .inner
            .clone();

        loop {
            if hashes.len() >= GAS_PRICE_BLOCK_SAMPLE_SIZE || epoch == 0 {
                break;
            }

            let mut epoch_hashes = inner.read().block_hashes_by_epoch(epoch)?;
            epoch_hashes.reverse();

            let missing = GAS_PRICE_BLOCK_SAMPLE_SIZE - hashes.len();
            hashes.extend(epoch_hashes.into_iter().take(missing));

            epoch -= 1;
        }

        // retrieve blocks in batches
        let mut stream = stream::iter(hashes)
            .map(|h| async move {
                self.retrieve_block(h).await.map(move |b| (h, b))
            })
            .buffered(GAS_PRICE_BATCH_SIZE);

        // collect gas price sample
        let mut prices = vec![];

        while let Some(item) = stream.try_next().await? {
            let block = match item {
                (_, Some(b)) => b,
                (hash, None) => {
                    // `retrieve_block` will only return None if we do not have
                    // the corresponding header, which should not happen in this
                    // case.
                    bail!(LightError::InternalError(format!(
                        "Block {:?} not found during gas price sampling",
                        hash
                    )));
                }
            };

            trace!("sampling gas prices from block {:?}", block.hash());
            processed_block_count += 1;
            total_transaction_count_in_processed_blocks +=
                block.transactions.len();

            for tx in block.transactions.iter() {
                prices.push(tx.gas_price().clone());

                if prices.len() == GAS_PRICE_TRANSACTION_SAMPLE_SIZE {
                    break;
                }
            }
        }

        trace!("gas price sample: {:?}", prices);

        let average_transaction_count_per_block = if processed_block_count != 0
        {
            total_transaction_count_in_processed_blocks / processed_block_count
        } else {
            0
        };

        if prices.is_empty() {
            Ok(Some(U256::from(1)))
        } else {
            prices.sort();
            if average_transaction_count_per_block
                < TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_LOW
            {
                Ok(Some(U256::from(1)))
            } else if average_transaction_count_per_block
                < TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_MEDIUM
            {
                Ok(Some(prices[prices.len() / 8]))
            } else {
                Ok(Some(prices[prices.len() / 2]))
            }
        }
    }

    fn account_key(address: &H160) -> Vec<u8> {
        StorageKey::new_account_key(&address)
            .with_native_space()
            .to_key_bytes()
    }

    fn code_key(address: &H160, code_hash: &H256) -> Vec<u8> {
        StorageKey::new_code_key(&address, &code_hash)
            .with_native_space()
            .to_key_bytes()
    }

    fn storage_key(address: &H160, position: &[u8]) -> Vec<u8> {
        StorageKey::new_storage_key(&address, &position)
            .with_native_space()
            .to_key_bytes()
    }

    fn deposit_list_key(address: &H160) -> Vec<u8> {
        StorageKey::new_deposit_list_key(address)
            .with_native_space()
            .to_key_bytes()
    }

    fn vote_list_key(address: &H160) -> Vec<u8> {
        StorageKey::new_vote_list_key(address)
            .with_native_space()
            .to_key_bytes()
    }

    pub async fn get_account(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<Account>, LightError> {
        debug!("get_account epoch={:?} address={:?}", epoch, address);

        let epoch = self.get_height_from_epoch_number(epoch)?;
        let key = Self::account_key(&address);

        match self.retrieve_state_entry_raw(epoch, key).await? {
            None => Ok(None),
            Some(rlp) => {
                Ok(Some(Account::new_from_rlp(address, &Rlp::new(&rlp))?))
            }
        }
    }

    pub async fn get_deposit_list(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<DepositList>, LightError> {
        let epoch = self.get_height_from_epoch_number(epoch)?;
        let key = Self::deposit_list_key(&address);
        self.retrieve_state_entry::<DepositList>(epoch, key).await
    }

    pub async fn get_vote_list(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<VoteStakeList>, LightError> {
        let epoch = self.get_height_from_epoch_number(epoch)?;
        let key = Self::vote_list_key(&address);
        self.retrieve_state_entry::<VoteStakeList>(epoch, key).await
    }

    pub async fn get_code(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<Option<Vec<u8>>, Error> {
        debug!("get_code epoch={:?} address={:?}", epoch, address);

        // do not query peers for non-contract addresses
        if !address.is_contract_address() && !address.is_builtin_address() {
            return Ok(None);
        }

        let epoch = self.get_height_from_epoch_number(epoch)?;
        let key = Self::account_key(&address);

        let code_hash = match self.retrieve_state_entry_raw(epoch, key).await {
            Err(e) => bail!(e),
            Ok(None) => return Ok(None),
            Ok(Some(rlp)) => {
                account_result_to_rpc_result(
                    "address",
                    Account::new_from_rlp(address, &Rlp::new(&rlp)),
                )?
                .code_hash
            }
        };

        let key = Self::code_key(&address, &code_hash);

        match self.retrieve_state_entry::<CodeInfo>(epoch, key).await? {
            None => {
                // this should not happen
                // if the corresponding state becomes unavailable between the
                // two requests, we will fail with timeout instead
                error!("Account {:?} found but code {:?} does not exist (epoch={:?})",  address, code_hash, epoch);
                Err(Error::Custom(format!(
                    "Unable to retrieve code: internal error"
                )))
            }
            Some(info) => Ok(Some((*info.code).clone())),
        }
    }

    pub async fn get_storage(
        &self, epoch: EpochNumber, address: H160, position: H256,
    ) -> Result<Option<H256>, LightError> {
        debug!(
            "get_storage epoch={:?} address={:?} position={:?}",
            epoch, address, position
        );

        let epoch = self.get_height_from_epoch_number(epoch)?;
        let key = Self::storage_key(&address, &position.0);

        match self.retrieve_state_entry::<StorageValue>(epoch, key).await {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(entry)) => Ok(Some(H256::from_uint(&entry.value))),
        }
    }

    pub async fn is_user_sponsored(
        &self, epoch: EpochNumber, contract: H160, user: H160,
    ) -> Result<bool, LightError> {
        debug!(
            "is_user_sponsored epoch={:?} contract={:?} user={:?}",
            epoch, contract, user
        );

        let epoch = self.get_height_from_epoch_number(epoch)?;

        // check if sponsorship is enabled for all users
        let all_sponsored = {
            let mut pos = Vec::with_capacity(H160::len_bytes() * 2);
            pos.extend_from_slice(contract.as_bytes());
            pos.extend_from_slice(COMMISSION_PRIVILEGE_SPECIAL_KEY.as_bytes());

            let key = Self::storage_key(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                &pos,
            );

            self.retrieve_state_entry::<StorageValue>(epoch, key)
        };

        // check if sponsorship is enabled for this specific user
        let user_sponsored = {
            let mut pos = Vec::with_capacity(H160::len_bytes() * 2);
            pos.extend_from_slice(contract.as_bytes());
            pos.extend_from_slice(user.as_bytes());

            let key = Self::storage_key(
                &SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
                &pos,
            );

            self.retrieve_state_entry::<StorageValue>(epoch, key)
        };

        // execute in parallel
        let (all_sponsored, user_sponsored) =
            future::join(all_sponsored, user_sponsored).await;

        if matches!(all_sponsored?, Some(n) if !n.value.is_zero()) {
            return Ok(true);
        }

        if matches!(user_sponsored?, Some(n) if !n.value.is_zero()) {
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn get_storage_root(
        &self, epoch: EpochNumber, address: H160,
    ) -> Result<StorageRoot, LightError> {
        debug!("get_storage_root epoch={:?} address={:?}", epoch, address);

        let epoch = self.get_height_from_epoch_number(epoch)?;
        self.retrieve_storage_root(epoch, address).await
    }

    pub async fn get_interest_rate(
        &self, epoch: EpochNumber,
    ) -> Result<U256, LightError> {
        debug!("get_interest_rate epoch={:?}", epoch);

        let epoch = self.get_height_from_epoch_number(epoch)?;

        let key = global_params::InterestRate::STORAGE_KEY.to_key_bytes();

        self.retrieve_state_entry::<U256>(epoch, key)
            .await
            .map(|opt| opt.unwrap_or_default())
    }

    pub async fn get_accumulate_interest_rate(
        &self, epoch: EpochNumber,
    ) -> Result<U256, LightError> {
        debug!("get_accumulate_interest_rate epoch={:?}", epoch);

        let epoch = self.get_height_from_epoch_number(epoch)?;

        let key =
            global_params::AccumulateInterestRate::STORAGE_KEY.to_key_bytes();

        self.retrieve_state_entry::<U256>(epoch, key)
            .await
            .map(|opt| opt.unwrap_or_default())
    }

    pub async fn get_pos_economics(
        &self, epoch: EpochNumber,
    ) -> Result<[U256; 3], LightError> {
        debug!("get_PoSEconomics epoch={:?}", epoch);

        let epoch = self.get_height_from_epoch_number(epoch)?;

        let key1 = global_params::TotalPosStaking::STORAGE_KEY.to_key_bytes();
        let key2 =
            global_params::DistributablePoSInterest::STORAGE_KEY.to_key_bytes();
        let key3 =
            global_params::LastDistributeBlock::STORAGE_KEY.to_key_bytes();

        let total_pos_staking = try_join!(
            self.retrieve_state_entry::<U256>(epoch, key1),
            self.retrieve_state_entry::<U256>(epoch, key2),
            self.retrieve_state_entry::<U256>(epoch, key3)
        )?;
        Ok([
            total_pos_staking.0.unwrap_or_default(),
            total_pos_staking.1.unwrap_or_default(),
            total_pos_staking.2.unwrap_or_default(),
        ])
    }

    pub async fn get_tx_info(&self, hash: H256) -> Result<TxInfo, LightError> {
        debug!("get_tx_info hash={:?}", hash);

        // Note: if a transaction does not exist, we fail with timeout, as
        //       peers cannot provide non-existence proofs for transactions.
        // FIXME: is there a better way?
        let TxInfoValidated {
            tx,
            receipt,
            tx_index,
            prior_gas_used,
        } = self.retrieve_tx_info(hash).await?;

        let block_hash = tx_index.block_hash;
        let maybe_epoch = self.consensus.get_block_epoch_number(&block_hash);
        let maybe_block_number =
            self.consensus.get_block_number(&block_hash)?;
        let maybe_state_root = maybe_epoch
            .and_then(|e| self.handler.witnesses.root_hashes_of(e).ok())
            .map(|roots| roots.state_root_hash);

        Ok(TxInfo {
            tx,
            maybe_block_number,
            receipt,
            tx_index,
            maybe_epoch,
            maybe_state_root,
            prior_gas_used,
        })
    }

    /// Relay raw transaction to all peers.
    // TODO(thegaram): consider returning TxStatus instead of bool,
    // e.g. Failed, Sent/Pending, Confirmed, etc.
    pub fn send_raw_tx(&self, raw: Vec<u8>) -> bool {
        debug!("send_raw_tx raw={:?}", raw);

        let peers = FullPeerFilter::new(msgid::SEND_RAW_TX)
            .select_all(self.handler.peers.clone());

        match self.network.with_context(
            self.handler.clone(),
            LIGHT_PROTOCOL_ID,
            |io| {
                let mut success = false;

                for peer in peers {
                    // relay to peer
                    let res = self.handler.send_raw_tx(io, &peer, raw.clone());

                    // check error
                    match res {
                        Err(e) => {
                            warn!("Failed to relay to peer={:?}: {:?}", peer, e)
                        }
                        Ok(_) => {
                            debug!("Tx relay to peer {:?} successful", peer);
                            success = true;
                        }
                    }
                }

                success
            },
        ) {
            Err(e) => unreachable!("{}", e),
            Ok(success) => success,
        }
    }

    pub async fn get_tx(
        &self, hash: H256,
    ) -> Result<SignedTransaction, LightError> {
        debug!("get_tx hash={:?}", hash);

        with_timeout(
            *MAX_POLL_TIME,
            format!(
                "Timeout while retrieving transaction with hash {:?}",
                hash
            ),
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
        filter: LogFilter,
    ) -> impl Iterator<Item = LocalizedLogEntry> {
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
        epoch: u64, hash: H256, block_receipts: BlockReceipts,
        filter: LogFilter,
    ) -> impl Iterator<Item = LocalizedLogEntry> {
        let mut receipts = block_receipts.receipts;
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
        &self, epoch: u64, mut receipts: Vec<BlockReceipts>, filter: LogFilter,
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

    pub fn get_latest_verifiable_chain_id(
        &self,
    ) -> Result<AllChainID, FilterError> {
        let epoch_number = self.get_latest_verifiable_epoch_number()?;
        Ok(self
            .consensus
            .get_config()
            .chain_id
            .read()
            .get_chain_id(epoch_number))
    }

    pub fn get_latest_verifiable_epoch_number(
        &self,
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
                });
            }
        };

        trace!(
            "get_latest_verifiable_epoch_number latest_verifiable = {}",
            latest_verifiable
        );
        Ok(latest_verifiable)
    }

    pub fn get_height_from_epoch_number(
        &self, epoch: EpochNumber,
    ) -> Result<u64, FilterError> {
        let latest_verifiable = self.get_latest_verifiable_epoch_number()?;

        trace!(
            "get_height_from_epoch_number epoch = {:?}, latest_verifiable = {}",
            epoch,
            latest_verifiable
        );

        match epoch {
            EpochNumber::Earliest => Ok(0),
            EpochNumber::LatestCheckpoint => {
                Ok(self.consensus.latest_checkpoint_epoch_number())
            }
            EpochNumber::LatestConfirmed => {
                Ok(self.consensus.latest_confirmed_epoch_number())
            }
            EpochNumber::LatestMined => Ok(latest_verifiable),
            EpochNumber::LatestState => Ok(latest_verifiable),
            EpochNumber::LatestFinalized => {
                Ok(self.consensus.latest_finalized_epoch_number())
            }
            EpochNumber::Number(n) if n <= latest_verifiable => Ok(n),
            EpochNumber::Number(n) => Err(FilterError::UnableToVerify {
                epoch: n,
                latest_verifiable,
            }),
        }
    }

    fn get_filter_epochs(
        &self, filter: &LogFilter,
    ) -> Result<(Vec<u64>, Box<dyn Fn(H256) -> bool + Send + Sync>), FilterError>
    {
        match &filter {
            LogFilter::EpochLogFilter {
                from_epoch,
                to_epoch,
                ..
            } => {
                let from_epoch =
                    self.get_height_from_epoch_number(from_epoch.clone())?;
                let to_epoch =
                    self.get_height_from_epoch_number(to_epoch.clone())?;

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
            LogFilter::BlockHashLogFilter { block_hashes, .. } => {
                // we use BTreeSet to make lookup efficient
                let hashes: BTreeSet<_> =
                    block_hashes.iter().cloned().collect();

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
            _ => bail!(FilterError::Custom(
                "Light nodes do not support log filtering using block numbers"
                    .into(),
            )),
        }
    }

    pub async fn get_logs(
        &self, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, LightError> {
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
                Ok(log) => Either::Right(self.retrieve_block_txs_for_log(log)),
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
            // Limit logs can return
            .take(self.consensus.get_config().get_logs_filter_max_limit.unwrap_or(::std::usize::MAX - 1) + 1)
            .try_collect();
        // --> TryFuture<Vec<LocalizedLogEntry>>

        let mut matching: Vec<_> = stream.await?;
        matching.reverse();
        debug!("Collected matching logs = {:?}", matching);
        Ok(matching)
    }

    pub fn get_network_type(&self) -> &Network {
        self.network.get_network_type()
    }
}
