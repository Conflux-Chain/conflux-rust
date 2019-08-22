// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use primitives::{BlockHeader, BlockHeaderBuilder};
use std::{ops::Index, sync::Arc};

use crate::light_protocol::{Error, ErrorKind};

pub enum LedgerProof {
    StateRoot(Vec<H256>),
    ReceiptsRoot(Vec<H256>),
}

impl Index<usize> for LedgerProof {
    type Output = H256;

    fn index(&self, ii: usize) -> &Self::Output {
        let hashes = match self {
            LedgerProof::StateRoot(hs) => hs,
            LedgerProof::ReceiptsRoot(hs) => hs,
        };

        &hashes[ii]
    }
}

impl LedgerProof {
    pub fn validate(&self, witness: Arc<BlockHeader>) -> Result<(), Error> {
        // extract proof hashes and corresponding local root hash
        let (hashes, local_root_hash) = match self {
            LedgerProof::StateRoot(hashes) => {
                (hashes, *witness.deferred_state_root())
            }
            LedgerProof::ReceiptsRoot(hashes) => {
                (hashes, *witness.deferred_receipts_root())
            }
        };

        // validate the number of hashes provided against local witness blame
        let blame = witness.blame() as u64;

        if hashes.len() as u64 != blame + 1 {
            info!(
                "Invalid number of hashes provided: expected={}, received={}",
                blame + 1,
                hashes.len()
            );
            return Err(ErrorKind::InvalidLedgerProof.into());
        }

        // compute witness deferred root hash from the hashes provided
        let received_root_hash = match blame {
            0 => hashes[0],
            _ => {
                let hashes = hashes.clone();
                BlockHeaderBuilder::compute_blame_state_root_vec_root(hashes)
            }
        };

        // validate against local witness deferred state root hash
        if received_root_hash != local_root_hash {
            info!(
                "Witness root hash mismatch: local={:?}, received={}",
                local_root_hash, received_root_hash
            );
            return Err(ErrorKind::InvalidLedgerProof.into());
        }

        Ok(())
    }
}
