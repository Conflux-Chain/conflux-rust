use std::collections::BTreeMap;

use cfx_types::{Address, AddressWithSpace, Space};
use cfx_vm_types::Spec;
use primitives::BlockNumber;

use super::{super::contracts::all_internal_contracts, InternalContractTrait};
use crate::spec::CommonParams;

#[derive(Default)]
pub struct InternalContractMap {
    builtin: BTreeMap<Address, Box<dyn InternalContractTrait>>,
    activation_info: BTreeMap<BlockNumber, Vec<Address>>,
}

impl std::ops::Deref for InternalContractMap {
    type Target = BTreeMap<Address, Box<dyn InternalContractTrait>>;

    fn deref(&self) -> &Self::Target { &self.builtin }
}

impl InternalContractMap {
    pub fn new(params: &CommonParams) -> Self {
        let mut builtin = BTreeMap::new();
        let mut activation_info = BTreeMap::new();
        // We should initialize all the internal contracts here. Even if not all
        // of them are activated at the genesis block. The activation of the
        // internal contracts are controlled by the `CommonParams` and
        // `vm::Spec`.
        let mut internal_contracts = all_internal_contracts();

        while let Some(contract) = internal_contracts.pop() {
            let address = *contract.address();
            let transition_block = if params.early_set_internal_contracts_states
            {
                0
            } else {
                contract.initialize_block(params)
            };

            builtin.insert(*contract.address(), contract);
            activation_info
                .entry(transition_block)
                .or_insert(vec![])
                .push(address);
        }

        Self {
            builtin,
            activation_info,
        }
    }

    #[cfg(test)]
    pub fn initialize_for_test() -> Vec<Address> {
        all_internal_contracts()
            .iter()
            .map(|contract| *contract.address())
            .collect()
    }

    pub fn initialized_at_genesis(&self) -> &[Address] {
        self.initialized_at(0)
    }

    pub fn initialized_at(&self, number: BlockNumber) -> &[Address] {
        self.activation_info
            .get(&number)
            .map_or(&[], |vec| vec.as_slice())
    }

    pub fn contract(
        &self, address: &AddressWithSpace, spec: &Spec,
    ) -> Option<&Box<dyn InternalContractTrait>> {
        if address.space != Space::Native {
            return None;
        }
        self.builtin
            .get(&address.address)
            .filter(|&contract| contract.is_active(spec))
    }
}
