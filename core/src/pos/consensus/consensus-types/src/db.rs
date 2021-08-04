use crate::block::Block;
use diem_crypto::HashValue;

pub trait LedgerBlockRW: Send + Sync {
    /// get_ledger_block
    fn get_ledger_block(
        &self, _block_id: &HashValue,
    ) -> anyhow::Result<Option<Block>> {
        unimplemented!()
    }

    /// save_ledger_blocks
    fn save_ledger_blocks(&self, _blocks: Vec<Block>) -> anyhow::Result<()> {
        unimplemented!()
    }
}

pub struct FakeLedgerBlockDB {}
impl LedgerBlockRW for FakeLedgerBlockDB {}
