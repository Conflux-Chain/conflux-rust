use cfx_rpc_cfx_types::traits::ChainMetaProvider;
use cfxcore::SharedConsensusGraph;

pub struct ChainInfo {
    consensus: SharedConsensusGraph,
}

impl ChainInfo {
    pub fn new(consensus: SharedConsensusGraph) -> Self { Self { consensus } }
}

impl ChainMetaProvider for ChainInfo {
    fn chain_id(&self) -> u32 { self.consensus.best_chain_id().in_evm_space() }
}
