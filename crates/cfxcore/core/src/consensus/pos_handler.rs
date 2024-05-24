use std::sync::{mpsc, Arc, Weak};

use once_cell::sync::OnceCell;

use cfx_types::{H256, U256, U64};
use diem_config::{config::NodeConfig, keys::ConfigKey};
use diem_crypto::HashValue;
use diem_types::{
    contract_event::ContractEvent,
    epoch_state::EpochState,
    reward_distribution_event::RewardDistributionEventV2,
    term_state::{DisputeEvent, UnlockEvent},
    validator_config::{ConsensusPrivateKey, ConsensusVRFPrivateKey},
};
use keccak_hash::keccak;
use primitives::pos::{NodeId, PosBlockId};
use storage_interface::{DBReaderForPoW, DbReader};

use crate::{
    genesis_block::GenesisPosState,
    pos::{
        consensus::{
            network::{
                NetworkReceivers as ConsensusNetworkReceivers,
                NetworkTask as ConsensusNetworkTask,
            },
            ConsensusDB, TestCommand,
        },
        mempool::network::{
            NetworkReceivers as MemPoolNetworkReceivers,
            NetworkTask as MempoolNetworkTask,
        },
        pos::{start_pos_consensus, PosDropHandle},
        protocol::sync_protocol::HotStuffSynchronizationProtocol,
    },
    sync::ProtocolConfiguration,
    ConsensusGraph,
};

use cached_pos_ledger_db::CachedPosLedgerDB;
use consensus_types::block::Block;
use diem_config::config::SafetyRulesTestConfig;
use diem_types::{
    account_address::from_consensus_public_key,
    block_info::{PivotBlockDecision, Round},
    chain_id::ChainId,
    epoch_state::HARDCODED_COMMITTEE_FOR_EPOCH,
    term_state::pos_state_config::{PosStateConfig, POS_STATE_CONFIG},
    transaction::TransactionPayload,
};
use network::NetworkService;
use parking_lot::Mutex;
use pos_ledger_db::PosLedgerDB;
use std::{fs, io::Read, path::PathBuf};

pub type PosVerifier = PosHandler;

/// This includes the interfaces that the PoW consensus needs from the PoS
/// consensus.
///
/// We assume the PoS service will be always available after `initialize()`
/// returns, so all the other interfaces will panic if the PoS service is not
/// ready.
pub trait PosInterface: Send + Sync {
    /// Wait for initialization.
    fn initialize(&self) -> Result<(), String>;

    /// Get a PoS block by its ID.
    ///
    /// Return `None` if the block does not exist or is not committed.
    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock>;

    /// Return the latest committed PoS block ID.
    /// This will become the PoS reference of the mined PoW block.
    fn latest_block(&self) -> PosBlockId;

    fn get_events(
        &self, from: &PosBlockId, to: &PosBlockId,
    ) -> Vec<ContractEvent>;

    fn get_epoch_ending_blocks(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Vec<PosBlockId>;

    fn get_reward_event(&self, epoch: u64)
        -> Option<RewardDistributionEventV2>;

    fn get_epoch_state(&self, block_id: &PosBlockId) -> EpochState;

    fn pos_ledger_db(&self) -> &Arc<PosLedgerDB>;

    fn consensus_db(&self) -> &Arc<ConsensusDB>;

    fn cached_db(&self) -> &Arc<CachedPosLedgerDB>;
}

#[allow(unused)]
pub struct PosBlock {
    hash: PosBlockId,
    epoch: u64,
    round: u64,
    pivot_decision: H256,
    version: u64,
    view: u64,
    /* parent: PosBlockId,
     * author: NodeId,
     * voters: Vec<NodeId>, */
}

pub struct PosHandler {
    pos: OnceCell<Box<dyn PosInterface>>,
    network: Mutex<Option<Arc<NetworkService>>>,
    // Keep all tokio Runtime so they will not be dropped directly.
    drop_handle: Mutex<Option<PosDropHandle>>,
    consensus_network_receiver: Mutex<Option<ConsensusNetworkReceivers>>,
    mempool_network_receiver: Mutex<Option<MemPoolNetworkReceivers>>,
    test_command_sender: Mutex<Option<channel::Sender<TestCommand>>>,
    enable_height: u64,
    hsb_protocol_handler: Option<Arc<HotStuffSynchronizationProtocol>>,
    pub conf: PosConfiguration,
}

impl PosHandler {
    pub fn new(
        network: Option<Arc<NetworkService>>, conf: PosConfiguration,
        enable_height: u64,
    ) -> Self {
        let mut pos = Self {
            pos: OnceCell::new(),
            network: Mutex::new(network.clone()),
            drop_handle: Mutex::new(None),
            consensus_network_receiver: Mutex::new(None),
            mempool_network_receiver: Mutex::new(None),
            test_command_sender: Mutex::new(None),
            enable_height,
            hsb_protocol_handler: None,
            conf,
        };
        if let Some(network) = &network {
            // initialize hotstuff protocol handler
            let (consensus_network_task, consensus_network_receiver) =
                ConsensusNetworkTask::new();
            let (mempool_network_task, mempool_network_receiver) =
                MempoolNetworkTask::new();
            let own_node_hash = keccak(
                network.net_key_pair().expect("Error node key").public(),
            );
            let protocol_handler =
                Arc::new(HotStuffSynchronizationProtocol::new(
                    own_node_hash,
                    consensus_network_task,
                    mempool_network_task,
                    pos.conf.protocol_conf.clone(),
                ));
            protocol_handler.clone().register(network.clone()).unwrap();
            *pos.consensus_network_receiver.lock() =
                Some(consensus_network_receiver);
            *pos.mempool_network_receiver.lock() =
                Some(mempool_network_receiver);
            pos.hsb_protocol_handler = Some(protocol_handler);
        }
        pos
    }

    pub fn initialize(
        &self, consensus: Arc<ConsensusGraph>,
    ) -> Result<(), String> {
        if self.pos.get().is_some() {
            warn!("Initializing already-initialized PosHandler!");
            return Ok(());
        }
        let pos_config_path = match self.conf.diem_conf_path.as_ref() {
            Some(path) => PathBuf::from(path),
            None => bail!("No pos config!"),
        };

        POS_STATE_CONFIG
            .set(self.conf.pos_state_config.clone())
            .map_err(|e| {
                format!("Failed to set pos state config: e={:?}", e)
            })?;
        let mut pos_config = NodeConfig::load(pos_config_path)
            .map_err(|e| format!("Failed to load node config: e={:?}", e))?;
        HARDCODED_COMMITTEE_FOR_EPOCH
            .set(pos_config.consensus.hardcoded_epoch_committee.clone())
            .map_err(|e| {
                format!("Failed to set hardcoded_epoch_committee: e={:?}", e)
            })?;

        pos_config.set_data_dir(pos_config.data_dir().to_path_buf());
        let pos_genesis = read_initial_nodes_from_file(
            self.conf.pos_initial_nodes_path.as_str(),
        )?;
        let network = self.network.lock().take().expect("pos not initialized");
        let (test_command_sender, test_command_receiver) =
            channel::new_test(1024);

        pos_config.consensus.safety_rules.test = Some(SafetyRulesTestConfig {
            author: from_consensus_public_key(
                &self.conf.bls_key.public_key(),
                &self.conf.vrf_key.public_key(),
            ),
            consensus_key: Some(self.conf.bls_key.clone()),
            execution_key: Some(self.conf.bls_key.clone()),
            waypoint: Some(pos_config.base.waypoint.waypoint()),
        });
        pos_config.consensus.safety_rules.vrf_private_key =
            Some(self.conf.vrf_key.clone());
        pos_config.consensus.safety_rules.export_consensus_key = true;
        pos_config.consensus.safety_rules.vrf_proposal_threshold =
            self.conf.vrf_proposal_threshold;
        pos_config.consensus.chain_id = ChainId::new(network.network_id());

        let pos_drop_handle = start_pos_consensus(
            &pos_config,
            network,
            self.conf.protocol_conf.clone(),
            Some((
                self.conf.bls_key.public_key(),
                self.conf.vrf_key.public_key(),
            )),
            pos_genesis,
            self.consensus_network_receiver
                .lock()
                .take()
                .expect("not initialized"),
            self.mempool_network_receiver
                .lock()
                .take()
                .expect("not initialized"),
            test_command_receiver,
            self.hsb_protocol_handler.clone().expect("set in new"),
        );
        debug!("PoS initialized");
        let pos_connection = PosConnection::new(
            pos_drop_handle.pos_ledger_db.clone(),
            pos_drop_handle.consensus_db.clone(),
            pos_drop_handle.cached_db.clone(),
        );
        pos_drop_handle.pow_handler.initialize(consensus);
        if self.pos.set(Box::new(pos_connection)).is_err() {
            bail!("PoS initialized twice!");
        }
        *self.test_command_sender.lock() = Some(test_command_sender);
        *self.drop_handle.lock() = Some(pos_drop_handle);
        Ok(())
    }

    pub fn config(&self) -> &PosConfiguration { &self.conf }

    fn pos(&self) -> &Box<dyn PosInterface> { self.pos.get().unwrap() }

    pub fn pos_option(&self) -> Option<&Box<dyn PosInterface>> {
        self.pos.get()
    }

    pub fn is_enabled_at_height(&self, height: u64) -> bool {
        height >= self.enable_height
    }

    pub fn is_committed(&self, h: &PosBlockId) -> bool {
        self.pos().get_committed_block(h).is_some()
    }

    /// Check if `me` is equal to or extends `preds` (parent and referees).
    ///
    /// Since committed PoS blocks form a chain, and no pos block should be
    /// skipped, we only need to check if the round of `me` is equal to or plus
    /// one compared with the predecessors' rounds.
    ///
    /// Return `false` if `me` or `preds` contains non-existent PoS blocks.
    pub fn verify_against_predecessors(
        &self, me: &PosBlockId, preds: &Vec<PosBlockId>,
    ) -> bool {
        let me_round = match self.pos().get_committed_block(me) {
            None => {
                warn!("No pos block for me={:?}", me);
                return false;
            }
            Some(b) => (b.epoch, b.round),
        };
        for p in preds {
            let p_round = match self.pos().get_committed_block(p) {
                None => {
                    warn!("No pos block for pred={:?}", p);
                    return false;
                }
                Some(b) => (b.epoch, b.round),
            };
            if me_round < p_round {
                warn!("Incorrect round: me={:?}, pred={:?}", me_round, p_round);
                return false;
            }
        }
        true
    }

    pub fn get_pivot_decision(&self, h: &PosBlockId) -> Option<H256> {
        // Return None if `pos` has not been initialized
        self.pos
            .get()?
            .get_committed_block(h)
            .map(|b| b.pivot_decision)
    }

    pub fn get_latest_pos_reference(&self) -> PosBlockId {
        self.pos().latest_block()
    }

    pub fn get_pos_view(&self, h: &PosBlockId) -> Option<u64> {
        self.pos().get_committed_block(h).map(|b| b.view)
    }

    pub fn get_unlock_nodes(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Vec<(NodeId, u64)> {
        let unlock_event_key = UnlockEvent::event_key();
        let mut unlock_nodes = Vec::new();
        for event in self.pos().get_events(parent_pos_ref, h) {
            if *event.key() == unlock_event_key {
                let unlock_event = UnlockEvent::from_bytes(event.event_data())
                    .expect("key checked");
                let node_id = H256::from_slice(unlock_event.node_id.as_ref());
                let votes = unlock_event.unlocked;
                unlock_nodes.push((node_id, votes));
            }
        }
        unlock_nodes
    }

    pub fn get_disputed_nodes(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Vec<NodeId> {
        let dispute_event_key = DisputeEvent::event_key();
        let mut disputed_nodes = Vec::new();
        for event in self.pos().get_events(parent_pos_ref, h) {
            if *event.key() == dispute_event_key {
                let dispute_event =
                    DisputeEvent::from_bytes(event.event_data())
                        .expect("key checked");
                disputed_nodes
                    .push(H256::from_slice(dispute_event.node_id.as_ref()));
            }
        }
        disputed_nodes
    }

    pub fn get_reward_distribution_event(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Option<Vec<(u64, RewardDistributionEventV2)>> {
        if h == parent_pos_ref {
            return None;
        }
        let me_block = self.pos().get_committed_block(h)?;
        let parent_block = self.pos().get_committed_block(parent_pos_ref)?;
        if me_block.epoch == parent_block.epoch {
            return None;
        }
        let mut events = Vec::new();
        for epoch in parent_block.epoch..me_block.epoch {
            events.push((epoch, self.pos().get_reward_event(epoch)?));
        }
        Some(events)
    }

    pub fn pos_ledger_db(&self) -> &Arc<PosLedgerDB> {
        self.pos().pos_ledger_db()
    }

    pub fn consensus_db(&self) -> &Arc<ConsensusDB> {
        self.pos().consensus_db()
    }

    pub fn cached_db(&self) -> &Arc<CachedPosLedgerDB> {
        self.pos().cached_db()
    }

    pub fn stop(&self) -> Option<(Weak<PosLedgerDB>, Weak<ConsensusDB>)> {
        self.network.lock().take();
        self.consensus_network_receiver.lock().take();
        self.mempool_network_receiver.lock().take();
        self.drop_handle.lock().take().map(|pos_drop_handle| {
            let pos_ledger_db = pos_drop_handle.pos_ledger_db.clone();
            let consensus_db = pos_drop_handle.consensus_db.clone();
            (
                Arc::downgrade(&pos_ledger_db),
                Arc::downgrade(&consensus_db),
            )
        })
    }
}

/// The functions used in tests to construct attack cases
impl PosHandler {
    pub fn force_vote_proposal(&self, block_id: H256) -> anyhow::Result<()> {
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::ForceVoteProposal(h256_to_diem_hash(
                &block_id,
            )))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))
    }

    pub fn force_propose(
        &self, round: U64, parent_block_id: H256,
        payload: Vec<TransactionPayload>,
    ) -> anyhow::Result<()> {
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::ForcePropose {
                round: round.as_u64(),
                parent_id: h256_to_diem_hash(&parent_block_id),
                payload,
            })
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))
    }

    pub fn trigger_timeout(&self, timeout_type: String) -> anyhow::Result<()> {
        let command = match timeout_type.as_str() {
            "local" => TestCommand::LocalTimeout,
            "proposal" => TestCommand::ProposalTimeOut,
            "new_round" => TestCommand::NewRoundTimeout,
            _ => anyhow::bail!("Unknown timeout type"),
        };
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(command)
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))
    }

    pub fn force_sign_pivot_decision(
        &self, pivot_decision: PivotBlockDecision,
    ) -> anyhow::Result<()> {
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::BroadcastPivotDecision(pivot_decision))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))
    }

    pub fn get_chosen_proposal(&self) -> anyhow::Result<Option<Block>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::GetChosenProposal(tx))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))?;
        rx.recv().map_err(|e| anyhow::anyhow!("recv: err={:?}", e))
    }

    pub fn stop_election(&self) -> anyhow::Result<Option<Round>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::StopElection(tx))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))?;
        rx.recv().map_err(|e| anyhow::anyhow!("recv: err={:?}", e))
    }

    pub fn start_voting(&self, initialize: bool) -> anyhow::Result<()> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::StartVoting((initialize, tx)))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))?;
        rx.recv()?
    }

    pub fn stop_voting(&self) -> anyhow::Result<()> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::StopVoting(tx))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))?;
        rx.recv()?
    }

    pub fn voting_status(&self) -> anyhow::Result<bool> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.test_command_sender
            .lock()
            .as_mut()
            .ok_or(anyhow::anyhow!("Pos not initialized!"))?
            .try_send(TestCommand::GetVotingStatus(tx))
            .map_err(|e| anyhow::anyhow!("try_send: err={:?}", e))?;
        Ok(rx.recv()?)
    }
}

pub struct PosConnection {
    pos_storage: Arc<PosLedgerDB>,
    consensus_db: Arc<ConsensusDB>,
    pos_cache_db: Arc<CachedPosLedgerDB>,
}

impl PosConnection {
    pub fn new(
        pos_storage: Arc<PosLedgerDB>, consensus_db: Arc<ConsensusDB>,
        pos_cache_db: Arc<CachedPosLedgerDB>,
    ) -> Self {
        Self {
            pos_storage,
            consensus_db,
            pos_cache_db,
        }
    }
}

impl PosInterface for PosConnection {
    fn initialize(&self) -> Result<(), String> { Ok(()) }

    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock> {
        debug!("get_committed_block: {:?}", h);
        let block_hash = h256_to_diem_hash(h);
        let committed_block = self
            .pos_storage
            .get_committed_block_by_hash(&block_hash)
            .ok()?;

        /*
        let parent;
        let author;
        if *h == PosBlockId::default() {
            // genesis has no block, and its parent/author will not be used.
            parent = PosBlockId::default();
            author = NodeId::default();
        } else {
            let block = self
                .pos_consensus_db
                .get_ledger_block(&block_hash)
                .map_err(|e| {
                    warn!("get_committed_block: err={:?}", e);
                    e
                })
                .ok()??;
            debug_assert_eq!(block.id(), block_hash);
            parent = diem_hash_to_h256(&block.parent_id());
            // NIL block has no author.
            author = H256::from_slice(block.author().unwrap_or(Default::default()).as_ref());
        }
         */
        debug!("pos_handler gets committed_block={:?}", committed_block);
        Some(PosBlock {
            hash: *h,
            epoch: committed_block.epoch,
            round: committed_block.round,
            pivot_decision: committed_block.pivot_decision.block_hash,
            view: committed_block.view,
            /* parent,
             * author,
             * voters: ledger_info
             *     .signatures()
             *     .keys()
             *     .map(|author| H256::from_slice(author.as_ref()))
             *     .collect(), */
            version: committed_block.version,
        })
    }

    fn latest_block(&self) -> PosBlockId {
        diem_hash_to_h256(
            &self
                .pos_storage
                .get_latest_ledger_info_option()
                .expect("Initialized")
                .ledger_info()
                .consensus_block_id(),
        )
    }

    fn get_events(
        &self, from: &PosBlockId, to: &PosBlockId,
    ) -> Vec<ContractEvent> {
        let start_version = self
            .pos_storage
            .get_committed_block_by_hash(&h256_to_diem_hash(from))
            .expect("err reading ledger info for from")
            .version;
        let end_version = self
            .pos_storage
            .get_committed_block_by_hash(&h256_to_diem_hash(to))
            .expect("err reading ledger info for to")
            .version;
        self.pos_storage
            .get_events_by_version(start_version, end_version)
            .expect("err reading events")
    }

    fn get_epoch_ending_blocks(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Vec<PosBlockId> {
        self.pos_storage
            .get_epoch_ending_blocks(start_epoch, end_epoch)
            .expect("err reading epoch ending blocks")
            .into_iter()
            .map(|h| diem_hash_to_h256(&h))
            .collect()
    }

    fn get_reward_event(
        &self, epoch: u64,
    ) -> Option<RewardDistributionEventV2> {
        self.pos_storage.get_reward_event(epoch).ok()
    }

    fn get_epoch_state(&self, block_id: &PosBlockId) -> EpochState {
        self.pos_storage
            .get_pos_state(&h256_to_diem_hash(block_id))
            .expect("parent of an ending_epoch block")
            .epoch_state()
            .clone()
    }

    fn pos_ledger_db(&self) -> &Arc<PosLedgerDB> { &self.pos_storage }

    fn consensus_db(&self) -> &Arc<ConsensusDB> { &self.consensus_db }

    fn cached_db(&self) -> &Arc<CachedPosLedgerDB> { &self.pos_cache_db }
}

pub struct PosConfiguration {
    pub bls_key: ConfigKey<ConsensusPrivateKey>,
    pub vrf_key: ConfigKey<ConsensusVRFPrivateKey>,
    pub diem_conf_path: Option<String>,
    pub protocol_conf: ProtocolConfiguration,
    pub pos_initial_nodes_path: String,
    pub vrf_proposal_threshold: U256,
    pub pos_state_config: PosStateConfig,
}

fn diem_hash_to_h256(h: &HashValue) -> PosBlockId { H256::from(h.as_ref()) }
fn h256_to_diem_hash(h: &PosBlockId) -> HashValue {
    HashValue::new(h.to_fixed_bytes())
}

pub fn save_initial_nodes_to_file(path: &str, genesis_nodes: GenesisPosState) {
    fs::write(path, serde_json::to_string(&genesis_nodes).unwrap()).unwrap();
}

pub fn read_initial_nodes_from_file(
    path: &str,
) -> Result<GenesisPosState, String> {
    let mut file = fs::File::open(path)
        .map_err(|e| format!("failed to open initial nodes file: {:?}", e))?;

    let mut nodes_str = String::new();
    file.read_to_string(&mut nodes_str)
        .map_err(|e| format!("failed to read initial nodes file: {:?}", e))?;

    serde_json::from_str(nodes_str.as_str())
        .map_err(|e| format!("failed to parse initial nodes file: {:?}", e))
}
