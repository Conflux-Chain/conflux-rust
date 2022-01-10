use super::VmObserve;
use crate::{
    executive::ExecutiveResult,
    vm::{ActionParams, Result as VmResult},
};
use cfx_state::tracer::{AddressPocket, StateTracer};
use cfx_types::U256;

#[derive(Default)]
pub struct GasMan {
    gas_cost: U256,
    gas_offer: Vec<U256>,
}

fn round_up(input: U256, depth: usize) -> U256 {
    let mut input = input;
    for _ in 0..depth {
        input = input * 64 / 63 + 1;
    }
    input
}

impl StateTracer for GasMan {
    fn trace_internal_transfer(
        &mut self, _: AddressPocket, _: AddressPocket, _: U256,
    ) {
    }
}

impl VmObserve for GasMan {
    fn record_call(&mut self, params: &ActionParams) {
        self.gas_offer.push(params.gas);
    }

    fn record_call_result(&mut self, result: &VmResult<ExecutiveResult>) {
        let gas_offer = self.gas_offer.pop().unwrap();
        let gas_left = match result {
            Ok(ExecutiveResult { gas_left, .. }) => gas_left.clone(),
            Err(_) => U256::zero(),
        };
        self.gas_cost += round_up(gas_offer - gas_left, self.gas_offer.len());
    }

    fn record_create(&mut self, params: &ActionParams) {
        self.gas_offer.push(params.gas)
    }

    fn record_create_result(&mut self, result: &VmResult<ExecutiveResult>) {
        let gas_offer = self.gas_offer.pop().unwrap();
        let gas_left = match result {
            Ok(ExecutiveResult { gas_left, .. }) => gas_left.clone(),
            Err(_) => U256::zero(),
        };
        self.gas_cost += round_up(gas_offer - gas_left, self.gas_offer.len());
    }
}
