use crate::storage::StateRootWithAuxInfo;
use cfx_types::{Address, H256, U256};
use parity_bytes::ToPretty;
use primitives::SignedTransaction;
use rlp::*;
use std::{fmt::Display, sync::Arc, vec::Vec};

#[derive(Debug)]
pub struct BlockHashAuthorValue<ValueType>(
    pub H256,
    pub Address,
    pub ValueType,
);

//#[derive(Debug)]
//pub struct BlockHashValue<ValueType>(pub H256, pub ValueType);

#[derive(Debug)]
pub struct AuthorValue<ValueType>(pub Address, pub ValueType);

#[derive(Debug)]
pub struct ComputeEpochDebugRecord {
    // Basic information.
    pub parent_block_hash: H256,
    pub parent_state_root: StateRootWithAuxInfo,
    pub reward_epoch_hash: Option<H256>,
    pub anticone_penalty_cutoff_epoch_hash: Option<H256>,

    // Blocks.
    pub block_hashes: Vec<H256>,
    pub block_txs: Vec<usize>,
    pub transactions: Vec<Arc<SignedTransaction>>,

    // Rewards. Rewards for anticone overlimit blocks may be skipped.
    pub block_authors: Vec<Address>,
    pub no_reward_blocks: Vec<H256>,
    pub block_rewards: Vec<BlockHashAuthorValue<U256>>,
    pub anticone_penalties: Vec<BlockHashAuthorValue<U256>>,
    //pub anticone_set_size: Vec<BlockHashValue<usize>>,
    pub tx_fees: Vec<BlockHashAuthorValue<U256>>,
    pub block_final_rewards: Vec<BlockHashAuthorValue<U256>>,
    pub merged_rewards_by_author: Vec<AuthorValue<U256>>,

    // State root sequence.
    // TODO: the fields below are not yet filled for debugging.
    pub state_roots_post_tx: Vec<H256>,
    pub state_root_after_applying_rewards: H256,

    // Storage operations.
    // op name, key, maybe_value
    pub state_ops: Vec<StateOp>,
}

#[derive(Debug)]
pub enum StateOp {
    OpNameKeyMaybeValue {
        op_name: String,
        key: Vec<u8>,
        maybe_value: Option<Vec<u8>>,
    },
}

impl Encodable for StateOp {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            StateOp::OpNameKeyMaybeValue {
                op_name,
                key,
                maybe_value,
            } => {
                s.begin_list(3)
                    .append(&(String::from("state_op ") + op_name))
                    .append(&key.as_slice())
                    .append(
                        &maybe_value.as_ref().map(|value| value.as_slice()),
                    );
            }
        }
    }
}

impl<ValueType: Display> Encodable for BlockHashAuthorValue<ValueType> {
    fn rlp_append(&self, s: &mut RlpStream) {
        // FIXME: U256 to dec string?
        s.begin_list(3)
            .append(&(String::from("block_hash: ") + &self.0.to_hex()))
            .append(&(String::from("author: ") + &self.1.to_hex()))
            .append(&self.2.to_string());
    }
}

//impl<ValueType: Display> Encodable for BlockHashValue<ValueType> {
//    fn rlp_append(&self, s: &mut RlpStream) {
//        s.begin_list(2)
//            .append(&(String::from("block_hash: ") + &self.0.hex()))
//            .append(&self.1.to_string());
//    }
//}

impl<ValueType: Display> Encodable for AuthorValue<ValueType> {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&(String::from("author: ") + &self.0.to_hex()))
            .append(&self.1.to_string());
    }
}

impl Encodable for ComputeEpochDebugRecord {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list();

        s.append(&"block_hashes").append_list(&self.block_hashes);
        s.append(&"block_transactions")
            .append_list::<String, String>(
                &self
                    .block_txs
                    .iter()
                    .map(|size| size.to_string())
                    .collect::<Vec<_>>(),
            );
        s.append(&"transactions")
            .append_list::<SignedTransaction, Arc<SignedTransaction>>(
                &self.transactions,
            );

        s.append(&"no_reward_blocks")
            .append_list(&self.no_reward_blocks);
        s.append(&"block_authors").append_list(&self.block_authors);
        s.append(&"block_rewards").append_list(&self.block_rewards);
        s.append(&"anticone_penalties")
            .append_list(&self.anticone_penalties);
        //        s.append(&"anticone_set_size")
        //            .append_list(&self.anticone_set_size);
        s.append(&"transaction_fees").append_list(&self.tx_fees);
        s.append(&"block_final_rewards")
            .append_list(&self.block_final_rewards);
        s.append(&"merged_rewards_by_author")
            .append_list(&self.merged_rewards_by_author);

        s.append(&"state_roots_post_tx")
            .append_list(&self.state_roots_post_tx);
        s.append(&"state_root_after_applying_rewards")
            .append(&self.state_root_after_applying_rewards);
        s.append(&"state_ops").append_list(&self.state_ops);

        s.complete_unbounded_list();
    }
}
