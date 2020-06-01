// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    error::{BlockError, Error},
    executive::Executive,
    parameters::block::*,
    pow::{self, nonce_to_lower_bound, ProofOfWorkProblem},
    storage::{make_simple_mpt, simple_mpt_merkle_root, TrieProof},
    sync::{Error as SyncError, ErrorKind as SyncErrorKind},
    vm,
};
use cfx_types::{BigEndianHash, H256, U256};
use primitives::{
    transaction::TransactionError, Action, Block, BlockHeader, BlockReceipts,
    MerkleHash, SignedTransaction, TransactionWithSignature,
};
use rlp::Encodable;
use std::{collections::HashSet, sync::Arc};
use unexpected::{Mismatch, OutOfBounds};

#[derive(Debug, Clone)]
pub struct VerificationConfig {
    pub verify_timestamp: bool,
    pub referee_bound: usize,
    pub max_block_size_in_bytes: usize,
    pub transaction_epoch_bound: u64,
    vm_spec: vm::Spec,
}

pub fn compute_transaction_root(
    transactions: &Vec<Arc<SignedTransaction>>,
) -> MerkleHash {
    simple_mpt_merkle_root(&mut make_simple_mpt(
        transactions
            .iter()
            .map(|tx| tx.hash.as_bytes().into())
            .collect(),
    ))
}

pub fn compute_receipts_root(receipts: &Vec<Arc<BlockReceipts>>) -> MerkleHash {
    let mut block_receipts_roots = Vec::with_capacity(receipts.len());
    for block_receipts in receipts {
        let block_receipts_root = simple_mpt_merkle_root(&mut make_simple_mpt(
            block_receipts
                .receipts
                .iter()
                .map(|receipt| receipt.rlp_bytes().into_boxed_slice())
                .collect(),
        ));
        block_receipts_roots.push(block_receipts_root.as_bytes().into());
    }
    simple_mpt_merkle_root(&mut make_simple_mpt(block_receipts_roots))
}

// FIXME:
//   Write a unit test with data from sample chain.
//   Pay attention to the index matching.
#[allow(unused)]
pub fn verify_tx_receipt_inclusion_proof(
    tx_hash: H256, block_index_in_epoch: usize, tx_index_in_block: usize,
    verified_transaction_root: MerkleHash, transaction_proof: TrieProof,
    verified_receipts_root: MerkleHash, block_index_proof: TrieProof,
    receipts_proof: TrieProof,
) -> bool
{
    unimplemented!()
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
    /// Note that this function returns *pow_hash* of the block, not its quality
    pub fn compute_pow_hash_and_fill_header_pow_quality(
        header: &mut BlockHeader,
    ) -> H256 {
        let nonce = header.nonce();
        let pow_hash = pow::compute(&nonce, &header.problem_hash());
        header.pow_quality = pow::pow_hash_to_quality(&pow_hash, &nonce);
        pow_hash
    }

    #[inline]
    pub fn verify_pow(&self, header: &mut BlockHeader) -> Result<(), Error> {
        let pow_hash =
            Self::compute_pow_hash_and_fill_header_pow_quality(header);
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
            &pow_hash,
            &header.nonce(),
            &boundary,
        ) {
            let lower_bound = nonce_to_lower_bound(&header.nonce());
            // Because the lower_bound first bit is always zero, as long as the
            // difficulty is not 1, this should not overflow.
            // We just use overflowing_add() here to be safe.
            let (upper_bound, _) = lower_bound.overflowing_add(boundary);
            warn!("block {} has invalid proof of work. boundary: [{}, {}), pow_hash: {}",
                  header.hash(), lower_bound.clone(), upper_bound.clone(), pow_hash.clone());
            return Err(From::from(BlockError::InvalidProofOfWork(
                OutOfBounds {
                    min: Some(BigEndianHash::from_uint(&lower_bound)),
                    max: Some(BigEndianHash::from_uint(&upper_bound)),
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
        let expected_root = compute_transaction_root(&block.transactions);
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
