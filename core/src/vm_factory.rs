// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    evm::{Factory as EvmFactory, VMType},
    vm::{ActionParams, Exec, Spec},
};

/// Virtual machine factory
#[derive(Default, Clone)]
pub struct VmFactory {
    evm: EvmFactory,
}

impl VmFactory {
    pub fn create(
        &self, params: ActionParams, spec: &Spec, depth: usize,
    ) -> Box<dyn Exec> {
        self.evm.create(params, spec, depth)
    }

    pub fn new(cache_size: usize) -> Self {
        VmFactory {
            evm: EvmFactory::new(VMType::Interpreter, cache_size),
        }
    }
}

impl From<EvmFactory> for VmFactory {
    fn from(evm: EvmFactory) -> Self {
        VmFactory { evm }
    }
}
