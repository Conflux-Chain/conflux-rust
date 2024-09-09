// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_executor::internal_contract::evm_map;
use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_rpc_cfx_types::{
    trace::{Action, LocalizedTrace},
    RpcAddress,
};
use cfx_rpc_eth_types::trace::LocalizedTrace as EthLocalizedTrace;
use cfx_types::H160;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochTrace {
    cfx_traces: Vec<LocalizedTrace>,
    eth_traces: Vec<EthLocalizedTrace>,
    mirror_address_map: HashMap<H160, RpcAddress>,
}

impl EpochTrace {
    pub fn new(
        cfx_traces: Vec<LocalizedTrace>, eth_traces: Vec<EthLocalizedTrace>,
    ) -> Self {
        let mut mirror_address_map = HashMap::new();
        for t in &cfx_traces {
            if let Action::Call(action) = &t.action {
                if action.to.hex_address == CROSS_SPACE_CONTRACT_ADDRESS {
                    mirror_address_map.insert(
                        evm_map(action.from.hex_address).address,
                        action.from.clone(),
                    );
                }
            }
        }
        Self {
            cfx_traces,
            eth_traces,
            mirror_address_map,
        }
    }
}
