// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    error::{BlockError, Error},
    pow,
};
use cfx_types::H256;
use primitives::{Block, BlockHeader};
use std::collections::HashSet;
use unexpected::{Mismatch, OutOfBounds};

#[derive(Debug, Copy, Clone)]
pub struct VerificationConfig {
    pub verify_timestamp: bool,
}

impl VerificationConfig {
    pub fn new(test_mode: bool) -> Self {
        if test_mode {
            VerificationConfig {
                verify_timestamp: false,
            }
        } else {
            VerificationConfig {
                verify_timestamp: true,
            }
        }
    }

    pub fn compute_header_pow_quality(header: &mut BlockHeader) -> H256 {
        let pow_hash = pow::compute(header.nonce(), &header.problem_hash());
        header.pow_quality = pow::boundary_to_difficulty(&pow_hash);
        pow_hash
    }

    pub fn verify_pow(&self, header: &mut BlockHeader) -> Result<(), Error> {
        let pow_hash = Self::compute_header_pow_quality(header);
        if header.difficulty().is_zero() {
            return Err(BlockError::InvalidDifficulty(Mismatch {
                expected: 0.into(),
                found: 0.into(),
            })
            .into());
        }
        let boundary = pow::difficulty_to_boundary(header.difficulty());
        if pow_hash >= boundary {
            warn!("block {} has invalid proof of work. boundary: {}, pow_hash: {}", header.hash(), boundary.clone(), pow_hash.clone());
            return Err(From::from(BlockError::InvalidProofOfWork(
                OutOfBounds {
                    min: None,
                    max: Some(boundary),
                    found: pow_hash,
                },
            )));
        }

        assert!(header.pow_quality >= *header.difficulty());

        Ok(())
    }

    /// Check basic header parameters.
    /// This does not require header to be graph or parental tree ready.
    pub fn verify_header_params(
        &self, header: &mut BlockHeader,
    ) -> Result<(), Error> {
        // verify POW
        self.verify_pow(header)?;

        // verify non-duplicated parent and referee hashes
        let mut direct_ancestor_hashes = HashSet::new();
        let parent_hash = header.parent_hash();
        direct_ancestor_hashes.insert(parent_hash.clone());
        for referee_hash in header.referee_hashes() {
            if direct_ancestor_hashes.contains(referee_hash) {
                warn!(
                    "block {} has duplicate parent or referee hashes",
                    header.hash()
                );
                return Err(From::from(
                    BlockError::DuplicateParentOrRefereeHashes(
                        referee_hash.clone(),
                    ),
                ));
            }
            direct_ancestor_hashes.insert(referee_hash.clone());
        }

        Ok(())
    }

    /// Verify block data against header: transactions root
    fn verify_block_integrity(&self, block: &Block) -> Result<(), Error> {
        let expected_root =
            Block::compute_transaction_root(&block.transactions);
        if &expected_root != block.block_header.transactions_root() {
            warn!("Invalid transaction root");
            bail!(BlockError::InvalidTransactionsRoot(Mismatch {
                expected: expected_root,
                found: *block.block_header.transactions_root(),
            }));
        }
        Ok(())
    }

    /// Phase 1 quick block verification. Only does checks that are cheap.
    /// Operates on a single block.
    /// Note that we should first check whether the block body matches its
    /// header, e.g., check transaction root correctness, and then check the
    /// body itself. If body does not match header, the block may still be
    /// valid but we get the wrong body from evil node. So we try to get
    /// body again from others. However, if the body matches the header and
    /// the body is incorrect, this means the block is invalid, and we
    /// should discard this block and all its descendants.
    // FIXME check block_size, gas_limit, tx_count, e.t.c.
    pub fn verify_block_basic(&self, block: &Block) -> Result<(), Error> {
        self.verify_block_integrity(block)?;

        for t in &block.transactions {
            t.transaction.verify_basic()?;
        }

        Ok(())
    }
}
