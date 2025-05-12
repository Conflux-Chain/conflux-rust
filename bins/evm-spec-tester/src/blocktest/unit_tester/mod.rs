use crate::{
    statetest::unit_tester::pre_transact::make_state, TestError, TestErrorKind,
};
use cfx_executor::{machine::Machine, state::State};
use cfx_types::{SpaceMap, U256};
use cfxcore::verification::VerificationConfig;
use eest_types::{BlockchainTestUnit, TestBlock};
use primitives::{Block, BlockHeaderBuilder, SignedTransaction};
use std::sync::Arc;

pub struct UnitTester {
    path: String,
    name: String,
    unit: BlockchainTestUnit,
}

impl UnitTester {
    pub fn new(path: &String, name: String, unit: BlockchainTestUnit) -> Self {
        UnitTester {
            path: path.clone(),
            name,
            unit,
        }
    }

    fn err(&self, kind: TestErrorKind) -> TestError {
        TestError {
            name: self.name.clone(),
            path: self.path.clone(),
            kind,
        }
    }

    pub fn run(
        &self, machine: &Machine, verification: &VerificationConfig,
        matches: Option<&str>,
    ) -> Result<usize, TestError> {
        if !matches.map_or(true, |pat| {
            format!("{}::{}", &self.path, &self.name).contains(pat)
        }) {
            return Ok(0);
        }

        if matches.is_some() {
            info!("Running TestUnit: {}", self.name);
        } else {
            trace!("Running TestUnit: {}", self.name);
        }

        let mut state = make_state(&self.unit.pre);

        let blocks = self.blocks();

        if blocks.iter().any(|block| block.is_err()) {
            return Err(
                self.err(TestErrorKind::Internal("invalid block test".into()))
            );
        }

        let epochs: Vec<Vec<Arc<Block>>> = blocks
            .into_iter()
            .map(|b| vec![Arc::new(b.unwrap())])
            .collect();

        for epoch in epochs {
            let _ = self.process_epoch(
                &mut state,
                machine,
                verification,
                &epoch,
                0,
            );
        }

        Ok(0)
    }

    fn process_epoch(
        &self, state: &mut State, machine: &Machine,
        verification: &VerificationConfig, epoch: &Vec<Arc<Block>>,
        start_block_number: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn blocks(&self) -> Vec<Result<Block, String>> {
        self.unit
            .blocks
            .iter()
            .map(|block| match block {
                TestBlock::Block(b) => {
                    let txs: Vec<Result<SignedTransaction, String>> = b
                        .transactions
                        .iter()
                        .map(|tx| tx.clone().try_into())
                        .collect();
                    if txs.iter().any(|tx| tx.is_err()) {
                        return Err("block have invalid tx".into());
                    }
                    let txs = txs
                        .into_iter()
                        .map(|tx| Arc::new(tx.unwrap()))
                        .collect();
                    let mut builder = BlockHeaderBuilder::new();
                    builder
                        .with_parent_hash(b.block_header.parent_hash)
                        .with_height(b.block_header.number.as_u64())
                        .with_timestamp(b.block_header.timestamp.as_u64())
                        .with_author(b.block_header.coinbase)
                        .with_transactions_root(
                            b.block_header.transactions_trie,
                        )
                        .with_deferred_state_root(b.block_header.state_root)
                        .with_deferred_receipts_root(
                            b.block_header.receipt_trie,
                        )
                        .with_deferred_logs_bloom_hash(keccak_hash::keccak(
                            b.block_header.bloom.data(),
                        ))
                        .with_difficulty(b.block_header.difficulty)
                        .with_gas_limit(b.block_header.gas_limit)
                        // use uncle_hashes as referee_hashes
                        .with_referee_hashes(
                            b.uncle_headers.iter().map(|h| h.hash).collect(),
                        )
                        .with_nonce(U256::from(b.block_header.nonce.as_u64()))
                        // todo: set pos_reference, blame, adaptive, custom
                        .with_base_price(
                            b.block_header
                                .base_fee_per_gas
                                .map(|x| SpaceMap::new(x, x)),
                        );
                    let header = builder.build();
                    let block = Block::new(header, txs);
                    Ok(block)
                }
                TestBlock::InvalidBlock(_invalid) => {
                    Err("invalid block".into())
                }
            })
            .collect()
    }
}
