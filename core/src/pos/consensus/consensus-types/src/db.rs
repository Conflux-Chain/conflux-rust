// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{block::Block, quorum_cert::QuorumCert};
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

    fn get_qc_for_block(
        &self, _block_id: &HashValue,
    ) -> anyhow::Result<Option<QuorumCert>> {
        unimplemented!()
    }
}

pub struct FakeLedgerBlockDB {}
impl LedgerBlockRW for FakeLedgerBlockDB {}
