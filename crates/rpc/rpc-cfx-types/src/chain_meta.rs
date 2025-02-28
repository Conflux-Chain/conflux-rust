use parity_version::conflux_client_version;

#[derive(Debug, Copy, Clone, Default)]
pub struct ChainStaticMeta;

impl ChainStaticMeta {
    const CHAIN_NAME: &'static str = "ConfluxNetwork";
    const PROTOCOL_VERSION: u64 = 65;

    pub fn chain_name() -> String { Self::CHAIN_NAME.to_string() }

    pub fn protocol_version() -> u64 { Self::PROTOCOL_VERSION }

    pub fn client_version() -> String { conflux_client_version!() }
}
