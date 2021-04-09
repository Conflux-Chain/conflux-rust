use cfx_types::H256;
use primitives::pos::{NodeId, PosBlockId};
use std::sync::atomic::{AtomicBool, Ordering};

pub type PosVerifier = PosHandler<PosConnection>;

/// This includes the interfaces that the PoW consensus needs from the PoS
/// consensus.
///
/// We assume the PoS service will be always available after `initialize()`
/// returns, so all the other interfaces will panic if the PoS service is not
/// ready.
trait PosInterface {
    /// Wait for initialization.
    fn initialize(&self) -> Result<(), String>;

    /// Get a PoS block by its ID.
    ///
    /// Return `None` if the block does not exist or is not committed.
    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock>;

    /// Return the latest committed PoS block ID.
    /// This will become the PoS reference of the mined PoW block.
    fn latest_block(&self) -> PosBlockId;
}

struct PosBlock {
    hash: PosBlockId,
    parent: PosBlockId,
    round: u64,
    pivot_decision: H256,
    unlock_txs: Vec<UnlockTransaction>,
}

struct UnlockTransaction {
    /// The node id to unlock.
    ///
    /// The management contract should unlock the corresponding account.
    node_id: NodeId,
}

pub struct PosHandler<PoS: PosInterface> {
    pos: PoS,
    enable_height: u64,
}

impl<PoS: PosInterface> PosHandler<PoS> {
    pub fn new(pos: PoS, enable_height: u64) -> Self {
        Self { pos, enable_height }
    }

    pub fn is_enabled_at_height(&self, height: u64) -> bool {
        height >= self.enable_height
    }

    pub fn is_committed(&self, h: &PosBlockId) -> bool {
        self.pos.get_committed_block(h).is_some()
    }

    /// Check if `me` is equal to or extends the predecessors.
    ///
    /// Since committed PoS blocks form a chain, we only need to check if the
    /// round of `me` is no less than the predecessors.
    /// Return `false` if `me` or `preds` contain non-existent PoS blocks.
    pub fn verify_against_predecessors(
        &self, me: &PosBlockId, preds: &Vec<PosBlockId>,
    ) -> bool {
        let me_round = match self.pos.get_committed_block(me) {
            None => return false,
            Some(b) => b.round,
        };
        for p in preds {
            let p_round = match self.pos.get_committed_block(p) {
                None => return false,
                Some(b) => b.round,
            };
            if me_round < p_round {
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
}

pub struct PosConnection {
    // pos_storage: Arc<dyn PersistentStorage<PosTransaction>>,
}

impl PosConnection {
    pub fn new() -> Self {
        Self {
            // pos_storage,
        }
    }
}

impl PosInterface for PosConnection {
    fn initialize(&self) -> Result<(), String> { todo!() }

    fn get_committed_block(&self, h: &PosBlockId) -> Option<PosBlock> {
        /*
        self.pos_storage.get_ledger_block(h).expect("pos storage err").into()
         */
        todo!()
    }

    fn latest_block(&self) -> PosBlockId { todo!() }
}
