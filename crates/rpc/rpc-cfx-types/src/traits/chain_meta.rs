use clap::crate_version;

pub trait ChainStaticMetaProvider {
    /// Returns the current chain name.
    fn chain_name(&self) -> String { "ConfluxNetwork".to_string() }

    /// Returns the current chain protocol version.
    fn protocol_version(&self) -> u64 { 65 }

    fn client_version(&self) -> String {
        parity_version::version(crate_version!())
    }
}

impl<T> ChainStaticMetaProvider for T {}

pub trait ChainMetaProvider: ChainStaticMetaProvider {
    /// Returns the current chain id.
    fn chain_id(&self) -> u32;

    /// Returns the current chain network id.
    fn network_id(&self) -> u32 { self.chain_id() }

    // /// Returns the current chain genesis hash.
    // fn genesis_hash(&self) -> String;

    // /// Returns the current chain block hash.
    // fn block_hash(&self) -> String;

    // Returns the current chain block number.
    // fn block_number(&self) -> u64;

    // /// Returns the current chain block timestamp.
    // fn block_timestamp(&self) -> u64;
}
