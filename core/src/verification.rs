// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    error::{BlockError, Error},
    executive::Executive,
    parameters::block::*,
    pow::{self, ProofOfWorkProblem},
    sync::{Error as SyncError, ErrorKind as SyncErrorKind},
    vm,
};
use cfx_types::{BigEndianHash, H256, U256};
use primitives::{
    transaction::TransactionError, Action, Block, BlockHeader,
    TransactionWithSignature,
};
use std::collections::HashSet;
use unexpected::{Mismatch, OutOfBounds};

#[derive(Debug, Clone)]
pub struct VerificationConfig {
    pub verify_timestamp: bool,
    pub referee_bound: usize,
    pub max_block_size_in_bytes: usize,
    pub transaction_epoch_bound: u64,
    vm_spec: vm::Spec,
}

impl VerificationConfig {
    pub fn new(
        test_mode: bool, referee_bound: usize, max_block_size_in_bytes: usize,
        transaction_epoch_bound: u64,
    ) -> Self
    {
        if test_mode {
            VerificationConfig {
                verify_timestamp: false,
                referee_bound,
                max_block_size_in_bytes,
                transaction_epoch_bound,
                vm_spec: vm::Spec::new_spec(),
            }
        } else {
            VerificationConfig {
                verify_timestamp: true,
                referee_bound,
                max_block_size_in_bytes,
                transaction_epoch_bound,
                vm_spec: vm::Spec::new_spec(),
            }
        }
    }

    #[inline]
    pub fn compute_header_pow_quality(header: &mut BlockHeader) -> H256 {
        let pow_hash = pow::compute(header.nonce(), &header.problem_hash());
        header.pow_quality = pow::pow_hash_to_quality(&pow_hash);
        pow_hash
    }

    #[inline]
    pub fn verify_pow(&self, header: &mut BlockHeader) -> Result<(), Error> {
        let pow_hash = Self::compute_header_pow_quality(header);
        if header.difficulty().is_zero() {
            return Err(BlockError::InvalidDifficulty(OutOfBounds {
                min: Some(0.into()),
                max: Some(0.into()),
                found: 0.into(),
            })
            .into());
        }
        let boundary = pow::difficulty_to_boundary(header.difficulty());
        if !ProofOfWorkProblem::validate_hash_against_boundary(
            &pow_hash, &boundary,
        ) {
            warn!("block {} has invalid proof of work. boundary: {}, pow_hash: {}", header.hash(), boundary.clone(), pow_hash.clone());
            return Err(From::from(BlockError::InvalidProofOfWork(
                OutOfBounds {
                    min: None,
                    max: Some(BigEndianHash::from_uint(&boundary)),
                    found: pow_hash,
                },
            )));
        }

        assert!(header.pow_quality >= *header.difficulty());

        Ok(())
    }

    #[inline]
    pub fn validate_header_timestamp(
        &self, header: &BlockHeader, now: u64,
    ) -> Result<(), SyncError> {
        let invalid_threshold = now + VALID_TIME_DRIFT;
        if header.timestamp() > invalid_threshold {
            warn!("block {} has incorrect timestamp", header.hash());
            return Err(SyncErrorKind::InvalidTimestamp.into());
        }
        Ok(())
    }

    /// Check basic header parameters.
    /// This does not require header to be graph or parental tree ready.
    #[inline]
    pub fn verify_header_params(
        &self, header: &mut BlockHeader,
    ) -> Result<(), Error> {
        // Check header custom data length
        let custom_len = header.custom().iter().fold(0, |acc, x| acc + x.len());
        if custom_len > HEADER_CUSTOM_LENGTH_BOUND {
            return Err(From::from(BlockError::TooLongCustomInHeader(
                OutOfBounds {
                    min: Some(0),
                    max: Some(HEADER_CUSTOM_LENGTH_BOUND),
                    found: custom_len,
                },
            )));
        }

        // verify POW
        self.verify_pow(header)?;

        // A block will be invalid if it has more than REFEREE_BOUND referees
        if header.referee_hashes().len() > self.referee_bound {
            return Err(From::from(BlockError::TooManyReferees(OutOfBounds {
                min: Some(0),
                max: Some(self.referee_bound),
                found: header.referee_hashes().len(),
            })));
        }

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
    #[inline]
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
    #[inline]
    pub fn verify_block_basic(
        &self, block: &Block, chain_id: u64,
    ) -> Result<(), Error> {
        self.verify_block_integrity(block)?;

        let mut block_size = 0;
        let mut block_total_gas = U256::zero();

        let block_height = block.block_header.height();
        for t in &block.transactions {
            self.verify_transaction_in_block(t, chain_id, block_height)?;
            block_size += t.rlp_size();
            block_total_gas += *t.gas_limit();
        }

        if block_size > self.max_block_size_in_bytes {
            return Err(From::from(BlockError::InvalidBlockSize(
                OutOfBounds {
                    min: None,
                    max: Some(self.max_block_size_in_bytes as u64),
                    found: block_size as u64,
                },
            )));
        }

        if block_total_gas > *block.block_header.gas_limit() {
            return Err(From::from(BlockError::InvalidBlockGasLimit(
                OutOfBounds {
                    min: Some(*block.block_header.gas_limit()),
                    max: Some(*block.block_header.gas_limit()),
                    found: block_total_gas,
                },
            )));
        }

        Ok(())
    }

    pub fn check_transaction_epoch_bound(
        tx: &TransactionWithSignature, block_height: u64,
        transaction_epoch_bound: u64,
    ) -> i8
    {
        if tx.epoch_height + transaction_epoch_bound < block_height {
            -1
        } else if tx.epoch_height > block_height + transaction_epoch_bound {
            1
        } else {
            0
        }
    }

    pub fn verify_transaction_epoch_height(
        tx: &TransactionWithSignature, block_height: u64,
        transaction_epoch_bound: u64,
    ) -> Result<(), TransactionError>
    {
        if Self::check_transaction_epoch_bound(
            tx,
            block_height,
            transaction_epoch_bound,
        ) == 0
        {
            Ok(())
        } else {
            bail!(TransactionError::EpochHeightOutOfBound {
                set: tx.epoch_height,
                block_height,
                transaction_epoch_bound,
            });
        }
    }

    pub fn verify_transaction_in_block(
        &self, tx: &TransactionWithSignature, chain_id: u64, block_height: u64,
    ) -> Result<(), TransactionError> {
        self.verify_transaction_common(tx, chain_id)?;
        Self::verify_transaction_epoch_height(
            tx,
            block_height,
            self.transaction_epoch_bound,
        )
    }

    pub fn verify_transaction_common(
        &self, tx: &TransactionWithSignature, chain_id: u64,
    ) -> Result<(), TransactionError> {
        tx.check_low_s()?;

        // Disallow unsigned transactions
        if tx.is_unsigned() {
            bail!(TransactionError::InvalidSignature(
                "Transaction is unsigned".into()
            ));
        }

        if tx.chain_id != chain_id {
            bail!(TransactionError::ChainIdMismatch {
                expected: chain_id,
                got: tx.chain_id,
            });
        }

        // check transaction intrinsic gas
        let tx_intrinsic_gas = Executive::gas_required_for(
            tx.action == Action::Create,
            &tx.data,
            &self.vm_spec,
        );
        if tx.gas < (tx_intrinsic_gas as usize).into() {
            bail!(TransactionError::NotEnoughBaseGas {
                required: tx_intrinsic_gas.into(),
                got: tx.gas
            });
        }

        Ok(())
    }
}
