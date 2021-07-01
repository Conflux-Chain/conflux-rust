// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    error::{BlockError, Error},
    executive::Executive,
    machine::Machine,
    pow::{self, nonce_to_lower_bound, PowComputer, ProofOfWorkProblem},
    sync::{Error as SyncError, ErrorKind as SyncErrorKind},
    vm::Spec,
};
use cfx_parameters::block::*;
use cfx_storage::{
    into_simple_mpt_key, make_simple_mpt, simple_mpt_merkle_root,
    simple_mpt_proof, SimpleMpt, TrieProof,
};
use cfx_types::{BigEndianHash, H256, U256};
use primitives::{
    transaction::TransactionError, Action, Block, BlockHeader, BlockReceipts,
    MerkleHash, Receipt, SignedTransaction, TransactionWithSignature,
};
use rlp::Encodable;
use std::{collections::HashSet, convert::TryInto, sync::Arc};
use unexpected::{Mismatch, OutOfBounds};

#[derive(Clone)]
pub struct VerificationConfig {
    pub verify_timestamp: bool,
    pub referee_bound: usize,
    pub max_block_size_in_bytes: usize,
    pub transaction_epoch_bound: u64,
    machine: Arc<Machine>,
}

/// Create an MPT from the ordered list of block transactions.
/// Keys are transaction indices, values are transaction hashes.
fn transaction_trie(transactions: &Vec<Arc<SignedTransaction>>) -> SimpleMpt {
    make_simple_mpt(
        transactions
            .iter()
            .map(|tx| tx.hash.as_bytes().into())
            .collect(),
    )
}

/// Compute block transaction root.
/// This value is stored in the `transactions_root` header field.
pub fn compute_transaction_root(
    transactions: &Vec<Arc<SignedTransaction>>,
) -> MerkleHash {
    simple_mpt_merkle_root(&mut transaction_trie(transactions))
}

/// Compute a proof for the `tx_index_in_block`-th transaction in a block.
pub fn compute_transaction_proof(
    transactions: &Vec<Arc<SignedTransaction>>, tx_index_in_block: usize,
) -> TrieProof {
    simple_mpt_proof(
        &mut transaction_trie(transactions),
        &into_simple_mpt_key(tx_index_in_block, transactions.len()),
    )
}

/// Create an MPT from the ordered list of block receipts.
/// Keys are receipt indices, values are RLP serialized receipts.
fn block_receipts_trie(block_receipts: &Vec<Receipt>) -> SimpleMpt {
    make_simple_mpt(
        block_receipts
            .iter()
            .map(|receipt| receipt.rlp_bytes().into_boxed_slice())
            .collect(),
    )
}

/// Compute block receipts root.
fn compute_block_receipts_root(block_receipts: &Vec<Receipt>) -> MerkleHash {
    simple_mpt_merkle_root(&mut block_receipts_trie(block_receipts))
}

/// Compute a proof for the `tx_index_in_block`-th receipt in a block.
pub fn compute_block_receipt_proof(
    block_receipts: &Vec<Receipt>, tx_index_in_block: usize,
) -> TrieProof {
    simple_mpt_proof(
        &mut block_receipts_trie(block_receipts),
        &into_simple_mpt_key(tx_index_in_block, block_receipts.len()),
    )
}

/// Create an MPT from the ordered list of epoch receipts.
/// Keys are block indices in the epoch, values are block receipts roots.
fn epoch_receipts_trie(epoch_receipts: &Vec<Arc<BlockReceipts>>) -> SimpleMpt {
    make_simple_mpt(
        epoch_receipts
            .iter()
            .map(|block_receipts| &block_receipts.receipts)
            .map(|rs| compute_block_receipts_root(&rs).as_bytes().into())
            .collect(),
    )
}

/// Compute epoch receipts root.
/// This value is stored in the `deferred_receipts_root` header field.
pub fn compute_receipts_root(
    epoch_receipts: &Vec<Arc<BlockReceipts>>,
) -> MerkleHash {
    simple_mpt_merkle_root(&mut epoch_receipts_trie(epoch_receipts))
}

pub struct EpochReceiptProof {
    pub block_index_proof: TrieProof,
    pub block_receipt_proof: TrieProof,
}

/// Compute a proof for the `tx_index_in_block`-th receipt
/// in the `block_index_in_epoch`-th block in an epoch.
pub fn compute_epoch_receipt_proof(
    epoch_receipts: &Vec<Arc<BlockReceipts>>, block_index_in_epoch: usize,
    tx_index_in_block: usize,
) -> EpochReceiptProof
{
    let block_receipt_proof = compute_block_receipt_proof(
        &epoch_receipts[block_index_in_epoch].receipts,
        tx_index_in_block,
    );

    let block_index_proof = simple_mpt_proof(
        &mut epoch_receipts_trie(epoch_receipts),
        &into_simple_mpt_key(block_index_in_epoch, epoch_receipts.len()),
    );

    EpochReceiptProof {
        block_index_proof,
        block_receipt_proof,
    }
}

/// Use `proof` to verify that `tx_hash` is indeed the `tx_index_in_block`-th
/// transaction in a block with `num_txs_in_block` transactions and transaction
/// root `block_tx_root`.
pub fn is_valid_tx_inclusion_proof(
    block_tx_root: MerkleHash, tx_index_in_block: usize,
    num_txs_in_block: usize, tx_hash: H256, proof: &TrieProof,
) -> bool
{
    let key = &into_simple_mpt_key(tx_index_in_block, num_txs_in_block);
    proof.is_valid_kv(key, Some(tx_hash.as_bytes()), &block_tx_root)
}

/// Use `block_index_proof` to get the correct block receipts trie root for the
/// `block_index_in_epoch`-th block in an epoch with `num_blocks_in_epoch`
/// blocks and receipts root `verified_epoch_receipts_root`.
/// Then, use `block_receipt_proof` to verify that `receipt` is indeed the
/// `tx_index_in_block`-th receipt in a block with `num_txs_in_block`
/// transactions and the transaction root from the previous step.
pub fn is_valid_receipt_inclusion_proof(
    verified_epoch_receipts_root: MerkleHash, block_index_in_epoch: usize,
    num_blocks_in_epoch: usize, block_index_proof: &TrieProof,
    tx_index_in_block: usize, num_txs_in_block: usize, receipt: &Receipt,
    block_receipt_proof: &TrieProof,
) -> bool
{
    // get block receipts root from block index trie (proof)
    // traversing along `key` also means we're validating the proof
    let key = &into_simple_mpt_key(block_index_in_epoch, num_blocks_in_epoch);

    let block_receipts_root_bytes =
        match block_index_proof.get_value(key, &verified_epoch_receipts_root) {
            (false, _) => return false,
            (true, None) => return false,
            (true, Some(val)) => val,
        };

    // parse block receipts root as H256
    let block_receipts_root: H256 = match TryInto::<[u8; 32]>::try_into(
        block_receipts_root_bytes,
    ) {
        Ok(hash) => hash.into(),
        Err(e) => {
            // this should not happen
            error!(
                "Invalid content found in valid MPT: key = {:?}, value = {:?}; error = {:?}",
                key, block_receipts_root_bytes, e,
            );
            return false;
        }
    };

    // validate receipt in the block receipts trie
    let key = &into_simple_mpt_key(tx_index_in_block, num_txs_in_block);

    block_receipt_proof.is_valid_kv(
        key,
        Some(&receipt.rlp_bytes()[..]),
        &block_receipts_root,
    )
}

impl VerificationConfig {
    pub fn new(
        test_mode: bool, referee_bound: usize, max_block_size_in_bytes: usize,
        transaction_epoch_bound: u64, machine: Arc<Machine>,
    ) -> Self
    {
        if test_mode {
            VerificationConfig {
                verify_timestamp: false,
                referee_bound,
                max_block_size_in_bytes,
                transaction_epoch_bound,
                machine,
            }
        } else {
            VerificationConfig {
                verify_timestamp: true,
                referee_bound,
                max_block_size_in_bytes,
                transaction_epoch_bound,
                machine,
            }
        }
    }

    #[inline]
    /// Note that this function returns *pow_hash* of the block, not its quality
    pub fn get_or_fill_header_pow_hash(
        pow: &PowComputer, header: &mut BlockHeader,
    ) -> H256 {
        if header.pow_hash.is_none() {
            header.pow_hash = Some(Self::compute_pow_hash(pow, header));
        }
        header.pow_hash.unwrap()
    }

    pub fn get_or_fill_header_pow_quality(
        pow: &PowComputer, header: &mut BlockHeader,
    ) -> U256 {
        let pow_hash = Self::get_or_fill_header_pow_hash(pow, header);
        pow::pow_hash_to_quality(&pow_hash, &header.nonce())
    }

    pub fn get_or_compute_header_pow_quality(
        pow: &PowComputer, header: &BlockHeader,
    ) -> U256 {
        let pow_hash = header
            .pow_hash
            .unwrap_or_else(|| Self::compute_pow_hash(pow, header));
        pow::pow_hash_to_quality(&pow_hash, &header.nonce())
    }

    fn compute_pow_hash(pow: &PowComputer, header: &BlockHeader) -> H256 {
        let nonce = header.nonce();
        pow.compute(&nonce, &header.problem_hash(), header.height())
    }

    #[inline]
    pub fn verify_pow(
        &self, pow: &PowComputer, header: &mut BlockHeader,
    ) -> Result<(), Error> {
        let pow_hash = Self::get_or_fill_header_pow_hash(pow, header);
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

        assert!(
            Self::get_or_fill_header_pow_quality(pow, header)
                >= *header.difficulty()
        );

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
        &self, pow: &PowComputer, header: &mut BlockHeader,
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

        // Note that this is just used to rule out deprecated blocks, so the
        // change of header struct actually happens before the change of
        // reward is reflected in the state root. The first state root
        // including results of new rewards will in the header after another
        // REWARD_EPOCH_COUNT + DEFERRED_STATE_EPOCH_COUNT epochs.
        if let Some(expected_custom_prefix) =
            self.machine.params().custom_prefix(header.height())
        {
            for (i, expected_bytes) in expected_custom_prefix.iter().enumerate()
            {
                let header_custum = header.custom();
                // Header custom is too short.
                let b =
                    header_custum.get(i).ok_or(BlockError::InvalidCustom(
                        header_custum.clone(),
                        expected_custom_prefix.clone(),
                    ))?;
                if b != expected_bytes {
                    return Err(BlockError::InvalidCustom(
                        header_custum.clone(),
                        expected_custom_prefix.clone(),
                    )
                    .into());
                }
            }
        }

        // verify POW
        self.verify_pow(pow, header)?;

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
        &self, block: &Block, chain_id: u32,
    ) -> Result<(), Error> {
        self.verify_block_integrity(block)?;

        let mut block_size = 0;
        let mut block_total_gas = U256::zero();

        let block_height = block.block_header.height();
        for t in &block.transactions {
            // In sync graph, we skim checks requires spec.
            self.verify_transaction_in_block(t, chain_id, block_height, None)?;
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
        &self, tx: &TransactionWithSignature, chain_id: u32, block_height: u64,
        vm_spec: Option<&Spec>,
    ) -> Result<(), TransactionError>
    {
        self.verify_transaction_common(tx, chain_id, vm_spec)?;
        Self::verify_transaction_epoch_height(
            tx,
            block_height,
            self.transaction_epoch_bound,
        )
    }

    pub fn verify_transaction_common(
        &self, tx: &TransactionWithSignature, chain_id: u32,
        vm_spec: Option<&Spec>,
    ) -> Result<(), TransactionError>
    {
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

        // Forbid zero-gas-price tx
        if tx.gas_price == 0.into() {
            bail!(TransactionError::ZeroGasPrice);
        }

        if let Some(spec) = vm_spec {
            // check transaction intrinsic gas
            let tx_intrinsic_gas = Executive::gas_required_for(
                tx.action == Action::Create,
                &tx.data,
                &spec,
            );
            if tx.gas < (tx_intrinsic_gas as usize).into() {
                bail!(TransactionError::NotEnoughBaseGas {
                    required: tx_intrinsic_gas.into(),
                    got: tx.gas
                });
            }
        }
        Ok(())
    }
}
