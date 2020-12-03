// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::builtin::Builtin;
use crate::{
    builtin::{builtin_factory, AltBn128PairingPricer, Linear, ModexpPricer},
    vm::Spec,
};
use cfx_internal_common::ChainIdParams;
use cfx_types::{Address, H256, U256};
use primitives::BlockNumber;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Default)]
pub struct CommonParams {
    /// Account start nonce.
    pub account_start_nonce: U256,
    /// Maximum size of extra data.
    pub maximum_extra_data_size: usize,
    /// Network id.
    pub network_id: u64,
    /// Chain id.
    pub chain_id: ChainIdParams,
    /// Main subprotocol name.
    pub subprotocol_name: String,
    /// Minimum gas limit.
    pub min_gas_limit: U256,
    /// Gas limit bound divisor (how much gas limit can change per block)
    pub gas_limit_bound_divisor: U256,
    /// Node permission managing contract address.
    pub node_permission_contract: Option<Address>,
    /// Maximum contract code size that can be deployed.
    pub max_code_size: u64,
    /// Number of first block where max code size limit is active.
    pub max_code_size_transition: BlockNumber,
    /// Maximum size of transaction's RLP payload.
    pub max_transaction_size: usize,

    /// Number of first block where ec built-in contract enabled.
    pub alt_bn128_transition: u64,
}

impl CommonParams {
    fn common_params(chain_id: ChainIdParams) -> Self {
        CommonParams {
            account_start_nonce: 0x00.into(),
            maximum_extra_data_size: 0x20,
            network_id: 0x1,
            chain_id,
            subprotocol_name: "cfx".into(),
            min_gas_limit: 10_000_000.into(),
            gas_limit_bound_divisor: 0x0400.into(),
            node_permission_contract: None,
            max_code_size: 24576,
            max_code_size_transition: 0,
            max_transaction_size: 300 * 1024,
            alt_bn128_transition: i64::MAX as u64, /* TODO: Update it when
                                                    * the time point of the
                                                    * next update enabled. */
        }
    }
}

pub type SpecCreationRules = dyn Fn(&mut Spec, BlockNumber) + Sync + Send;

pub struct Machine {
    params: CommonParams,
    builtins: Arc<BTreeMap<Address, Builtin>>,
    spec_rules: Option<Box<SpecCreationRules>>,
}

impl Machine {
    pub fn builtin(
        &self, address: &Address, block_number: BlockNumber,
    ) -> Option<&Builtin> {
        self.builtins.get(address).and_then(|b| {
            if b.is_active(block_number) {
                Some(b)
            } else {
                None
            }
        })
    }

    /// Attach special rules to the creation of spec.
    pub fn set_spec_creation_rules(&mut self, rules: Box<SpecCreationRules>) {
        self.spec_rules = Some(rules);
    }

    /// Get the general parameters of the chain.
    pub fn params(&self) -> &CommonParams { &self.params }

    pub fn spec(&self, number: BlockNumber) -> Spec {
        let mut spec = Spec::new_spec();
        if let Some(ref rules) = self.spec_rules {
            (rules)(&mut spec, number)
        }
        spec
    }

    /// Builtin-contracts for the chain..
    pub fn builtins(&self) -> &BTreeMap<Address, Builtin> { &*self.builtins }
}

pub fn new_machine(chain_id: ChainIdParams) -> Machine {
    Machine {
        params: CommonParams::common_params(chain_id),
        builtins: Arc::new(BTreeMap::new()),
        spec_rules: None,
    }
}

pub fn new_machine_with_builtin(chain_id: ChainIdParams) -> Machine {
    let mut btree = BTreeMap::new();
    let params = CommonParams::common_params(chain_id);
    btree.insert(
        Address::from(H256::from_low_u64_be(1)),
        Builtin::new(
            Box::new(Linear::new(3000, 0)),
            builtin_factory("ecrecover"),
            0,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(2)),
        Builtin::new(
            Box::new(Linear::new(60, 12)),
            builtin_factory("sha256"),
            0,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(3)),
        Builtin::new(
            Box::new(Linear::new(600, 120)),
            builtin_factory("ripemd160"),
            0,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(4)),
        Builtin::new(
            Box::new(Linear::new(15, 3)),
            builtin_factory("identity"),
            0,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(5)),
        Builtin::new(
            Box::new(ModexpPricer::new(20)),
            builtin_factory("modexp"),
            params.alt_bn128_transition,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(6)),
        Builtin::new(
            Box::new(Linear::new(500, 0)),
            builtin_factory("alt_bn128_add"),
            params.alt_bn128_transition,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(7)),
        Builtin::new(
            Box::new(Linear::new(40_000, 0)),
            builtin_factory("alt_bn128_mul"),
            params.alt_bn128_transition,
        ),
    );
    btree.insert(
        Address::from(H256::from_low_u64_be(8)),
        Builtin::new(
            Box::new(AltBn128PairingPricer::new(100_000, 80_000)),
            builtin_factory("alt_bn128_pairing"),
            params.alt_bn128_transition,
        ),
    );
    Machine {
        params,
        builtins: Arc::new(btree),
        spec_rules: None,
    }
}
