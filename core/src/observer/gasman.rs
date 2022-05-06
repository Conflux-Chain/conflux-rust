use super::VmObserve;
use crate::{
    executive::ExecutiveResult,
    vm::{ActionParams, Result as VmResult},
};
use cfx_parameters::{
    block::CROSS_SPACE_GAS_RATIO,
    internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS,
};
use cfx_state::tracer::{AddressPocket, StateTracer};
use cfx_types::U256;

const EVM_RATIO: (u64, u64) = (64, 63);
const CROSS_SPACE_RATIO: (u64, u64) = (CROSS_SPACE_GAS_RATIO, 1);

struct ExecutiveLevel {
    init_gas: U256,
    gas_cost_in_subcall: U256,
    gas_limit_for_subcall: U256,
    cross_space_internal: bool,
}

impl ExecutiveLevel {
    #[inline]
    fn gas_cost(&self, gas_left: &U256) -> U256 {
        // Due to gas stipend, the gas_left could be larger than gas cost.
        self.init_gas.saturating_sub(*gas_left)
    }

    #[inline]
    fn gas_cost_this_level(&self, gas_left: &U256) -> U256 {
        self.gas_cost(gas_left)
            .saturating_sub(self.gas_cost_in_subcall)
    }

    #[inline]
    fn minimum_init_gas(&self, gas_left: &U256, ratio: (u64, u64)) -> U256 {
        let (numerator, denominator) = ratio;
        self.gas_cost_this_level(gas_left)
            + (self.gas_limit_for_subcall * numerator + denominator - 1)
                / denominator
    }
}

#[derive(Default)]
pub struct GasMan {
    gas_limit: U256,
    gas_record: Vec<ExecutiveLevel>,
}

impl GasMan {
    pub fn gas_required(&self) -> U256 { self.gas_limit }

    fn record_call_create(
        &mut self, gas_pass_in: &U256, cross_space_internal: bool,
    ) {
        self.gas_record.push(ExecutiveLevel {
            init_gas: gas_pass_in.clone(),
            gas_cost_in_subcall: U256::zero(),
            gas_limit_for_subcall: U256::zero(),
            cross_space_internal,
        })
    }

    fn record_return(&mut self, gas_left: &U256) {
        let child_level = self.gas_record.pop().unwrap();
        let ratio = if child_level.cross_space_internal {
            CROSS_SPACE_RATIO
        } else {
            EVM_RATIO
        };

        if let Some(ExecutiveLevel {
            gas_cost_in_subcall,
            gas_limit_for_subcall,
            ..
        }) = self.gas_record.last_mut()
        {
            *gas_cost_in_subcall += child_level.gas_cost(gas_left);
            *gas_limit_for_subcall +=
                child_level.minimum_init_gas(gas_left, ratio);
        } else {
            self.gas_limit = child_level.minimum_init_gas(gas_left, ratio);
        }
    }
}

impl StateTracer for GasMan {
    fn trace_internal_transfer(
        &mut self, _: AddressPocket, _: AddressPocket, _: U256,
    ) {
    }

    fn checkpoint(&mut self) {}

    fn discard_checkpoint(&mut self) {}

    fn revert_to_checkpoint(&mut self) {}
}

impl VmObserve for GasMan {
    fn record_call(&mut self, params: &ActionParams) {
        let cross_space_internal =
            params.code_address == *CROSS_SPACE_CONTRACT_ADDRESS;
        self.record_call_create(&params.gas, cross_space_internal);
    }

    fn record_call_result(&mut self, result: &VmResult<ExecutiveResult>) {
        let gas_left =
            result.as_ref().map_or(U256::zero(), |r| r.gas_left.clone());
        self.record_return(&gas_left);
    }

    fn record_create(&mut self, params: &ActionParams) {
        self.record_call_create(&params.gas, false);
    }

    fn record_create_result(&mut self, result: &VmResult<ExecutiveResult>) {
        let gas_left =
            result.as_ref().map_or(U256::zero(), |r| r.gas_left.clone());
        self.record_return(&gas_left);
    }
}
