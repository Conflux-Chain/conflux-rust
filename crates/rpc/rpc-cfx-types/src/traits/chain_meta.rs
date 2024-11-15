use crate::ChainStaticMeta;

pub trait ChainMetaProvider {
    /// Returns the current chain id.
    fn chain_id(&self) -> u32;

    /// Returns the current chain network id.
    fn network_id(&self) -> u32 { self.chain_id() }

    fn meta() -> ChainStaticMeta { ChainStaticMeta }

    // /// Returns the current chain genesis hash.
    // fn genesis_hash(&self) -> String;

    // /// Returns the current chain block hash.
    // fn block_hash(&self) -> String;

    // Returns the current chain block number.
    // fn block_number(&self) -> u64;

    // /// Returns the current chain block timestamp.
    // fn block_timestamp(&self) -> u64;
}
