// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::pos_handler::PosVerifier,
    core_error::{BlockError, CoreError as Error},
    pow::{self, nonce_to_lower_bound, PowComputer, ProofOfWorkProblem},
    sync::Error as SyncError,
};
use cfx_executor::{
    executive::gas_required_for, machine::Machine, spec::TransitionsEpochHeight,
};
use cfx_parameters::{block::*, consensus_internal::ELASTICITY_MULTIPLIER};
use cfx_storage::{
    into_simple_mpt_key, make_simple_mpt, simple_mpt_merkle_root,
    simple_mpt_proof, SimpleMpt, TrieProof,
};
use cfx_types::{
    address_util::AddressUtil, AllChainID, BigEndianHash, Space, SpaceMap,
    H256, U256,
};
use cfx_vm_types::Spec;
use primitives::{
    block::BlockHeight,
    block_header::compute_next_price_tuple,
    transaction::{
        native_transaction::TypedNativeTransaction, TransactionError,
    },
    Action, Block, BlockHeader, BlockReceipts, MerkleHash, Receipt,
    SignedTransaction, Transaction, TransactionWithSignature,
};
use rlp::Encodable;
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashSet, convert::TryInto, sync::Arc};
use unexpected::{Mismatch, OutOfBounds};

#[derive(Clone)]
pub struct VerificationConfig {
    pub verify_timestamp: bool,
    pub referee_bound: usize,
    pub max_block_size_in_bytes: usize,
    pub transaction_epoch_bound: u64,
    pub max_nonce: Option<U256>,
    machine: Arc<Machine>,
    pos_verifier: Arc<PosVerifier>,
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

#[derive(
    Clone,
    Debug,
    RlpEncodable,
    RlpDecodable,
    Default,
    PartialEq,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct EpochReceiptProof {
    pub block_index_proof: TrieProof,
    pub block_receipt_proof: TrieProof,
}

/// Compute a proof for the `tx_index_in_block`-th receipt
/// in the `block_index_in_epoch`-th block in an epoch.
pub fn compute_epoch_receipt_proof(
    epoch_receipts: &Vec<Arc<BlockReceipts>>, block_index_in_epoch: usize,
    tx_index_in_block: usize,
) -> EpochReceiptProof {
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
) -> bool {
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
) -> bool {
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
        transaction_epoch_bound: u64, tx_pool_nonce_bits: usize,
        machine: Arc<Machine>, pos_verifier: Arc<PosVerifier>,
    ) -> Self {
        let max_nonce = if tx_pool_nonce_bits < 256 {
            Some((U256::one() << tx_pool_nonce_bits) - 1)
        } else {
            None
        };
        if test_mode {
            VerificationConfig {
                verify_timestamp: false,
                referee_bound,
                max_block_size_in_bytes,
                transaction_epoch_bound,
                machine,
                pos_verifier,
                max_nonce,
            }
        } else {
            VerificationConfig {
                verify_timestamp: true,
                referee_bound,
                max_block_size_in_bytes,
                transaction_epoch_bound,
                machine,
                pos_verifier,
                max_nonce,
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
            return Err(SyncError::InvalidTimestamp.into());
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

        if self.pos_verifier.is_enabled_at_height(header.height()) {
            if header.pos_reference().is_none() {
                bail!(BlockError::MissingPosReference);
            }
        } else {
            if header.pos_reference().is_some() {
                bail!(BlockError::UnexpectedPosReference);
            }
        }

        if header.height() >= self.machine.params().transition_heights.cip1559 {
            if header.base_price().is_none() {
                bail!(BlockError::MissingBaseFee);
            }
        } else {
            if header.base_price().is_some() {
                bail!(BlockError::UnexpectedBaseFee);
            }
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
    pub fn verify_sync_graph_block_basic(
        &self, block: &Block, chain_id: AllChainID,
    ) -> Result<(), Error> {
        self.verify_block_integrity(block)?;

        let block_height = block.block_header.height();

        let mut block_size = 0;
        let transitions = &self.machine.params().transition_heights;

        for t in &block.transactions {
            self.verify_transaction_common(
                t,
                chain_id,
                block_height,
                transitions,
                VerifyTxMode::Remote,
            )?;
            block_size += t.rlp_size();
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
        Ok(())
    }

    pub fn verify_sync_graph_ready_block(
        &self, block: &Block, parent: &BlockHeader,
    ) -> Result<(), Error> {
        let mut total_gas: SpaceMap<U256> = SpaceMap::default();
        for t in &block.transactions {
            total_gas[t.space()] += *t.gas_limit();
        }

        if block.block_header.height()
            >= self.machine.params().transition_heights.cip1559
        {
            self.check_base_fee(block, parent, total_gas)?;
        } else {
            self.check_hard_gas_limit(block, total_gas)?;
        }
        Ok(())
    }

    fn check_hard_gas_limit(
        &self, block: &Block, total_gas: SpaceMap<U256>,
    ) -> Result<(), Error> {
        let block_height = block.block_header.height();

        let evm_space_gas_limit =
            if self.machine.params().can_pack_evm_transaction(block_height) {
                *block.block_header.gas_limit()
                    / self.machine.params().evm_transaction_gas_ratio
            } else {
                U256::zero()
            };

        let evm_total_gas = total_gas[Space::Ethereum];
        let block_total_gas = total_gas.map_sum(|x| *x);

        if evm_total_gas > evm_space_gas_limit {
            return Err(From::from(BlockError::InvalidPackedGasLimit(
                OutOfBounds {
                    min: None,
                    max: Some(evm_space_gas_limit),
                    found: evm_total_gas,
                },
            )));
        }

        if block_total_gas > *block.block_header.gas_limit() {
            return Err(From::from(BlockError::InvalidPackedGasLimit(
                OutOfBounds {
                    min: None,
                    max: Some(*block.block_header.gas_limit()),
                    found: block_total_gas,
                },
            )));
        }

        Ok(())
    }

    fn check_base_fee(
        &self, block: &Block, parent: &BlockHeader, total_gas: SpaceMap<U256>,
    ) -> Result<(), Error> {
        use Space::*;

        let params = self.machine.params();
        let cip1559_init = params.transition_heights.cip1559;
        let block_height = block.block_header.height();

        assert!(block_height >= cip1559_init);

        let core_gas_limit = block.block_header.core_space_gas_limit();
        let espace_gas_limit = block
            .block_header
            .espace_gas_limit(params.can_pack_evm_transaction(block_height));

        if total_gas[Ethereum] > espace_gas_limit {
            return Err(From::from(BlockError::InvalidPackedGasLimit(
                OutOfBounds {
                    min: None,
                    max: Some(espace_gas_limit),
                    found: total_gas[Ethereum],
                },
            )));
        }

        if total_gas[Native] > core_gas_limit {
            return Err(From::from(BlockError::InvalidPackedGasLimit(
                OutOfBounds {
                    min: None,
                    max: Some(core_gas_limit),
                    found: total_gas[Native],
                },
            )));
        }

        let parent_base_price = if block_height == cip1559_init {
            params.init_base_price()
        } else {
            parent.base_price().unwrap()
        };

        let gas_limit = SpaceMap::new(core_gas_limit, espace_gas_limit);
        let gas_target = gas_limit.map_all(|x| x / ELASTICITY_MULTIPLIER);
        let min_base_price = params.min_base_price();

        let expected_base_price = SpaceMap::zip4(
            gas_target,
            total_gas,
            parent_base_price,
            min_base_price,
        )
        .map_all(compute_next_price_tuple);

        let actual_base_price = block.block_header.base_price().unwrap();

        if actual_base_price != expected_base_price {
            return Err(From::from(BlockError::InvalidBasePrice(Mismatch {
                expected: expected_base_price,
                found: actual_base_price,
            })));
        }

        Ok(())
    }

    pub fn check_transaction_epoch_bound(
        tx: &TypedNativeTransaction, block_height: u64,
        transaction_epoch_bound: u64,
    ) -> i8 {
        if tx.epoch_height().wrapping_add(transaction_epoch_bound)
            < block_height
        {
            -1
        } else if *tx.epoch_height() > block_height + transaction_epoch_bound {
            1
        } else {
            0
        }
    }

    fn verify_transaction_epoch_height(
        tx: &TypedNativeTransaction, block_height: u64,
        transaction_epoch_bound: u64, mode: &VerifyTxMode,
    ) -> Result<(), TransactionError> {
        let result = Self::check_transaction_epoch_bound(
            tx,
            block_height,
            transaction_epoch_bound,
        );
        let allow_larger_epoch = mode.is_maybe_later();

        if result == 0 || (result > 0 && allow_larger_epoch) {
            Ok(())
        } else {
            bail!(TransactionError::EpochHeightOutOfBound {
                set: *tx.epoch_height(),
                block_height,
                transaction_epoch_bound,
            });
        }
    }

    fn fast_recheck_inner<F>(spec: &Spec, f: F) -> (bool, bool)
    where F: Fn(&VerifyTxMode) -> bool {
        let tx_pool_mode =
            VerifyTxMode::Local(VerifyTxLocalMode::MaybeLater, spec);
        let packing_mode = VerifyTxMode::Local(VerifyTxLocalMode::Full, spec);

        (f(&packing_mode), f(&tx_pool_mode))
    }

    pub fn fast_recheck(
        &self, tx: &TransactionWithSignature, height: BlockHeight,
        transitions: &TransitionsEpochHeight, spec: &Spec,
    ) -> PackingCheckResult {
        let cip90a = height >= transitions.cip90a;
        let cip1559 = height >= transitions.cip1559;

        let (can_pack, later_pack) =
            Self::fast_recheck_inner(spec, |mode: &VerifyTxMode| {
                if !Self::check_eip1559_transaction(tx, cip1559, mode) {
                    return false;
                }

                if let Transaction::Native(ref tx) = tx.unsigned {
                    Self::verify_transaction_epoch_height(
                        tx,
                        height,
                        self.transaction_epoch_bound,
                        mode,
                    )
                    .is_ok()
                } else {
                    Self::check_eip155_transaction(tx, cip90a, mode)
                }
            });

        match (can_pack, later_pack) {
            (true, _) => PackingCheckResult::Pack,
            (false, true) => PackingCheckResult::Pending,
            (false, false) => PackingCheckResult::Drop,
        }
    }

    // Packing transactions, verifying transaction in sync graph and inserting
    // transactions may have different logics. But they share a lot of similar
    // rules. We combine them together for convenient in the future upgrades..
    pub fn verify_transaction_common(
        &self, tx: &TransactionWithSignature, chain_id: AllChainID,
        height: BlockHeight, transitions: &TransitionsEpochHeight,
        mode: VerifyTxMode,
    ) -> Result<(), TransactionError> {
        tx.check_low_s()?;
        tx.check_y_parity()?;

        // Disallow unsigned transactions
        if tx.is_unsigned() {
            bail!(TransactionError::InvalidSignature(
                "Transaction is unsigned".into()
            ));
        }

        if let Some(tx_chain_id) = tx.chain_id() {
            if tx_chain_id != chain_id.in_space(tx.space()) {
                bail!(TransactionError::ChainIdMismatch {
                    expected: chain_id.in_space(tx.space()),
                    got: tx_chain_id,
                    space: tx.space(),
                });
            }
        }

        // Forbid zero-gas-price tx
        if tx.gas_price().is_zero() {
            bail!(TransactionError::ZeroGasPrice);
        }

        if matches!(mode, VerifyTxMode::Local(..))
            && tx.space() == Space::Native
        {
            if let Action::Call(ref address) = tx.transaction.action() {
                if !address.is_genesis_valid_address() {
                    bail!(TransactionError::InvalidReceiver)
                }
            }
        }

        if let (VerifyTxMode::Local(..), Some(max_nonce)) =
            (mode, self.max_nonce)
        {
            if tx.nonce() > &max_nonce {
                bail!(TransactionError::TooLargeNonce)
            }
        }

        // ******************************************
        // Each constraint depends on a mode or a CIP should be
        // implemented in a seperated function.
        // ******************************************
        let cip76 = height >= transitions.cip76;
        let cip90a = height >= transitions.cip90a;
        let cip130 = height >= transitions.cip130;
        let cip1559 = height >= transitions.cip1559;

        if let Transaction::Native(ref tx) = tx.unsigned {
            Self::verify_transaction_epoch_height(
                tx,
                height,
                self.transaction_epoch_bound,
                &mode,
            )?;
        }

        if !Self::check_eip155_transaction(tx, cip90a, &mode) {
            bail!(TransactionError::FutureTransactionType);
        }

        if !Self::check_eip1559_transaction(tx, cip1559, &mode) {
            bail!(TransactionError::FutureTransactionType)
        }

        Self::check_gas_limit(tx, cip76, &mode)?;
        Self::check_gas_limit_with_calldata(tx, cip130)?;

        Ok(())
    }

    fn check_eip155_transaction(
        tx: &TransactionWithSignature, cip90a: bool, mode: &VerifyTxMode,
    ) -> bool {
        if tx.space() == Space::Native {
            return true;
        }

        use VerifyTxLocalMode::*;
        match mode {
            VerifyTxMode::Local(Full, spec) => cip90a && spec.cip90,
            VerifyTxMode::Local(MaybeLater, _spec) => true,
            VerifyTxMode::Remote => cip90a,
        }
    }

    fn check_eip1559_transaction(
        tx: &TransactionWithSignature, cip1559: bool, mode: &VerifyTxMode,
    ) -> bool {
        if tx.is_legacy() {
            return true;
        }

        use VerifyTxLocalMode::*;
        match mode {
            VerifyTxMode::Local(Full, _spec) => cip1559,
            VerifyTxMode::Local(MaybeLater, _spec) => true,
            VerifyTxMode::Remote => cip1559,
        }
    }

    /// Check transaction intrinsic gas. Influenced by CIP-76.
    fn check_gas_limit(
        tx: &TransactionWithSignature, cip76: bool, mode: &VerifyTxMode,
    ) -> Result<(), TransactionError> {
        const GENESIS_SPEC: Spec = Spec::genesis_spec();
        let maybe_spec = if let VerifyTxMode::Local(_, spec) = mode {
            // In local mode, we check gas limit as usual.
            Some(*spec)
        } else if !cip76 {
            // In remote mode, we only check gas limit before cip-76 activated.
            Some(&GENESIS_SPEC)
        } else {
            None
        };

        if let Some(spec) = maybe_spec {
            let tx_intrinsic_gas = gas_required_for(
                *tx.action() == Action::Create,
                &tx.data(),
                tx.access_list(),
                &spec,
            );
            if *tx.gas() < (tx_intrinsic_gas as usize).into() {
                bail!(TransactionError::NotEnoughBaseGas {
                    required: tx_intrinsic_gas.into(),
                    got: *tx.gas()
                });
            }
        }

        Ok(())
    }

    fn check_gas_limit_with_calldata(
        tx: &TransactionWithSignature, cip130: bool,
    ) -> Result<(), TransactionError> {
        if !cip130 {
            return Ok(());
        }
        let data_length = tx.data().len();
        let min_gas_limit = data_length.saturating_mul(100);
        if tx.gas() < &U256::from(min_gas_limit) {
            bail!(TransactionError::NotEnoughBaseGas {
                required: min_gas_limit.into(),
                got: *tx.gas()
            });
        }
        Ok(())
    }

    pub fn check_tx_size(
        &self, tx: &TransactionWithSignature,
    ) -> Result<(), TransactionError> {
        if tx.rlp_size() > self.max_block_size_in_bytes {
            bail!(TransactionError::TooBig)
        } else {
            Ok(())
        }
    }
}

#[derive(Copy, Clone)]
pub enum PackingCheckResult {
    Pack,
    // Transaction can be packed.
    Pending,
    // Transaction may be ready to packed in the future.
    Drop, // Transaction can never be packed.
}

#[derive(Copy, Clone)]
pub enum VerifyTxMode<'a> {
    /// Check transactions in local mode, may have more constraints
    Local(VerifyTxLocalMode, &'a Spec),
    /// Check transactions for received blocks in sync graph, may have less
    /// constraints
    Remote,
}

#[derive(Copy, Clone)]
pub enum VerifyTxLocalMode {
    /// Apply all checks
    Full,
    /// If a transaction is not valid now, but can become valid in the future,
    /// the check sould pass
    MaybeLater,
}

impl<'a> VerifyTxMode<'a> {
    fn is_maybe_later(&self) -> bool {
        if let VerifyTxMode::Local(VerifyTxLocalMode::MaybeLater, _) = self {
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::verification::EpochReceiptProof;
    use cfx_storage::{
        CompressedPathRaw, TrieProof, TrieProofNode, VanillaChildrenTable,
    };

    #[test]
    fn test_rlp_epoch_receipt_proof() {
        let proof = EpochReceiptProof::default();
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());

        let serialized = serde_json::to_string(&proof).unwrap();
        let deserialized: EpochReceiptProof =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(proof, deserialized);

        let node1 = TrieProofNode::new(
            Default::default(),
            Some(Box::new([0x03, 0x04, 0x05])),
            CompressedPathRaw::new(
                &[0x00, 0x01, 0x02],
                CompressedPathRaw::first_nibble_mask(),
            ),
            /* path_without_first_nibble = */ true,
        );

        let root_node = {
            let mut children_table = VanillaChildrenTable::default();
            unsafe {
                *children_table.get_child_mut_unchecked(2) =
                    *node1.get_merkle();
                *children_table.get_children_count_mut() = 1;
            }
            TrieProofNode::new(
                children_table,
                None,
                CompressedPathRaw::default(),
                /* path_without_first_nibble = */ false,
            )
        };
        let nodes = [root_node, node1]
            .iter()
            .cloned()
            .cycle()
            .take(20)
            .collect();
        let proof = TrieProof::new(nodes).unwrap();

        let epoch_proof = EpochReceiptProof {
            block_index_proof: proof.clone(),
            block_receipt_proof: proof,
        };

        assert_eq!(
            epoch_proof,
            rlp::decode(&rlp::encode(&epoch_proof)).unwrap()
        );

        let serialized = serde_json::to_string(&epoch_proof).unwrap();
        let deserialized: EpochReceiptProof =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(epoch_proof, deserialized);
    }
}
