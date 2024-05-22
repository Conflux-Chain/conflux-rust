/// Helper [Inspector] that keeps track of gas.
#[derive(Clone, Copy, Debug, Default)]
pub struct GasInspector {
    gas_remaining: u64,
    last_gas_cost: u64,
}

impl GasInspector {
    pub fn gas_remaining(&self) -> u64 { self.gas_remaining }

    pub fn last_gas_cost(&self) -> u64 { self.last_gas_cost }

    pub fn set_gas_remainning(&mut self, remainning: u64) {
        self.gas_remaining = remainning;
    }

    pub fn set_last_gas_cost(&mut self, gas_cost: u64) {
        self.last_gas_cost = gas_cost;
    }
}
