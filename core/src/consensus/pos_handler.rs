use cfx_types::H256;
use diem_crypto::HashValue;
use diem_types::{
    account_config, contract_event::ContractEvent, event::EventKey,
    ledger_info::LedgerInfoWithSignatures,
};
use primitives::pos::{NodeId, PosBlockId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use storage_interface::DBReaderForPoW;

pub type PosVerifier = PosHandler<PosConnection>;

/// This includes the interfaces that the PoW consensus needs from the PoS
/// consensus.
///
/// We assume the PoS service will be always available after `initialize()`
/// returns, so all the other interfaces will panic if the PoS service is not
/// ready.
pub trait PosInterface {
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
}

#[allow(unused)]
pub struct PosBlock {
    hash: PosBlockId,
    round: u64,
    pivot_decision: H256,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct UnlockEvent {
    /// The node id to unlock.
    ///
    /// The management contract should unlock the corresponding account.
    pub node_id: NodeId,
}

impl UnlockEvent {
    pub fn unlock_event_key() -> EventKey {
        EventKey::new_from_address(
            &account_config::pivot_chain_select_address(),
            5,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bcs::from_bytes(bytes).map_err(Into::into)
    }
}

pub struct PosHandler<PoS: PosInterface> {
    pos: PoS,
    enable_height: u64,
}

impl<PoS: PosInterface> PosHandler<PoS> {
    pub fn new(pos: PoS, enable_height: u64) -> Self {
        pos.initialize().expect("PoS handler initialization error");
        Self { pos, enable_height }
    }

    pub fn is_enabled_at_height(&self, height: u64) -> bool {
        height >= self.enable_height
    }

    pub fn is_committed(&self, h: &PosBlockId) -> bool {
        self.pos.get_committed_block(h).is_some()
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
        let me_round = match self.pos.get_committed_block(me) {
            None => {
                warn!("No pos block for me={:?}", me);
                return false;
            }
            Some(b) => b.round,
        };
        for p in preds {
            let p_round = match self.pos.get_committed_block(p) {
                None => {
                    warn!("No pos block for pred={:?}", p);
                    return false;
                }
                Some(b) => b.round,
            };
            // FIXME(lpl): Decide if we want to allow pos blocks to be skipped.
            // || me_round > p_round + 1
            if me_round < p_round {
                warn!("Incorrect round: me={}, pred={}", me_round, p_round);
                return false;
            }
        }
        true
    }

    pub fn get_pivot_decision(&self, h: &PosBlockId) -> Option<H256> {
        self.pos.get_committed_block(h).map(|b| b.pivot_decision)
    }

    pub fn get_latest_pos_reference(&self) -> PosBlockId {
        self.pos.latest_block()
    }

    pub fn get_unlock_events(
        &self, h: &PosBlockId, parent_pos_ref: &PosBlockId,
    ) -> Vec<UnlockEvent> {
        let unlock_event_key = UnlockEvent::unlock_event_key();
        let mut unlock_events = Vec::new();
        for event in self.pos.get_events(parent_pos_ref, h) {
            if *event.key() == unlock_event_key {
                unlock_events.push(
                    UnlockEvent::from_bytes(event.event_data())
                        .expect("key checked"),
                );
            }
        }
        unlock_events
    }
}

pub struct PosConnection {
    pos_storage: Arc<dyn DBReaderForPoW>,
}

impl PosConnection {
    pub fn new(
        pos_storage: Arc<dyn DBReaderForPoW>, _conf: PosConfiguration,
    ) -> Self {
        Self { pos_storage }
    }
}

impl PosInterface for PosConnection {
    fn initialize(&self) -> Result<(), String> { Ok(()) }

    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock> {
        debug!("get_committed_block: {:?}", h);
        let ledger_info = self
            .pos_storage
            .get_block_ledger_info(&h256_to_diem_hash(h))
            .map_err(|e| {
                warn!("get_committed_block: err={:?}", e);
                e
            })
            .ok()?;
        debug!("pos_handler gets ledger_info={:?}", ledger_info);
        Some(PosBlock {
            hash: diem_hash_to_h256(
                &ledger_info.ledger_info().consensus_block_id(),
            ),
            round: ledger_info.ledger_info().round(),
            pivot_decision: ledger_info
                .ledger_info()
                .pivot_decision()
                .unwrap()
                .block_hash,
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
            .get_block_ledger_info(&h256_to_diem_hash(from))
            .expect("err reading ledger info for from")
            .ledger_info()
            .version();
        let end_version = self
            .pos_storage
            .get_block_ledger_info(&h256_to_diem_hash(to))
            .expect("err reading ledger info for from")
            .ledger_info()
            .version();
        self.pos_storage
            .get_events_by_version(start_version, end_version)
            .expect("err reading events")
    }
}

pub struct PosConfiguration {}

fn diem_hash_to_h256(h: &HashValue) -> PosBlockId { H256::from(h.as_ref()) }
fn h256_to_diem_hash(h: &PosBlockId) -> HashValue {
    HashValue::new(h.to_fixed_bytes())
}

pub struct FakeDiemDB {}
impl DBReaderForPoW for FakeDiemDB {
    fn get_latest_ledger_info_option(
        &self,
    ) -> Option<LedgerInfoWithSignatures> {
        todo!()
    }

    fn get_block_ledger_info(
        &self, _consensus_block_id: &HashValue,
    ) -> anyhow::Result<LedgerInfoWithSignatures> {
        todo!()
    }

    fn get_events_by_version(
        &self, _start_version: u64, _end_version: u64,
    ) -> anyhow::Result<Vec<ContractEvent>> {
        todo!()
    }
}
