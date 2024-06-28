// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_vm_interpreter::{Factory as EvmFactory, VMType};
use cfx_vm_types::{ActionParams, Exec, Spec};

/// Virtual machine factory
#[derive(Default, Clone)]
pub struct VmFactory {
    evm_factory: EvmFactory,
}

impl VmFactory {
    pub fn create(
        &self, params: ActionParams, spec: &Spec, depth: usize,
    ) -> Box<dyn Exec> {
        self.evm_factory.create(params, spec, depth)
    }

    pub fn new(cache_size: usize) -> Self {
        VmFactory {
            evm_factory: EvmFactory::new(VMType::Interpreter, cache_size),
        }
    }
}

impl From<EvmFactory> for VmFactory {
    fn from(evm_factory: EvmFactory) -> Self { VmFactory { evm_factory } }
}
