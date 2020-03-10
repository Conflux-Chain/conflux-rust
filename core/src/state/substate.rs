// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::CleanupMode;
use crate::evm::{CleanDustMode, Spec};
use cfx_types::Address;
use primitives::LogEntry;
use std::collections::{HashMap, HashSet};

/// State changes which should be applied in finalize,
/// after transaction is fully executed.
#[derive(Debug, Default)]
pub struct Substate {
    /// Any accounts that have suicided.
    pub suicides: HashSet<Address>,

    /// Any accounts that are touched.
    pub touched: HashSet<Address>,

    /// Any accounts that occupy some storage.
    pub storage_occupied: HashMap<Address, u64>,

    /// Any accounts that release some storage.
    pub storage_released: HashMap<Address, u64>,

    /// Any logs.
    pub logs: Vec<LogEntry>,

    /// Refund counter of SSTORE.
    pub sstore_clears_refund: i128,

    /// Created contracts.
    pub contracts_created: Vec<Address>,
}

impl Substate {
    /// Creates new substate.
    pub fn new() -> Self { Substate::default() }

    /// Merge secondary substate `s` into self, accruing each element
    /// correspondingly.
    pub fn accrue(&mut self, s: Substate) {
        self.suicides.extend(s.suicides);
        self.touched.extend(s.touched);
        self.logs.extend(s.logs);
        self.sstore_clears_refund += s.sstore_clears_refund;
        self.contracts_created.extend(s.contracts_created);
        for (address, amount) in s.storage_occupied {
            *self.storage_occupied.entry(address).or_insert(0) += amount;
        }
        for (address, amount) in s.storage_released {
            *self.storage_released.entry(address).or_insert(0) += amount;
        }
    }

    /// Get the cleanup mode object from this.
    pub fn to_cleanup_mode(&mut self, spec: &Spec) -> CleanupMode {
        match (
            spec.kill_dust != CleanDustMode::Off,
            spec.no_empty,
            spec.kill_empty,
        ) {
            (false, false, _) => CleanupMode::ForceCreate,
            (false, true, false) => CleanupMode::NoEmpty,
            (false, true, true) | (true, _, _) => {
                CleanupMode::TrackTouched(&mut self.touched)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Substate;
    use cfx_types::Address;
    use primitives::LogEntry;

    #[test]
    fn created() {
        let sub_state = Substate::new();
        assert_eq!(sub_state.suicides.len(), 0);
    }

    #[test]
    fn accrue() {
        let mut sub_state = Substate::new();
        sub_state
            .contracts_created
            .push(Address::from_low_u64_be(1));
        sub_state.logs.push(LogEntry {
            address: Address::from_low_u64_be(1),
            topics: vec![],
            data: vec![],
        });
        sub_state.sstore_clears_refund = (15000 * 5).into();
        sub_state.suicides.insert(Address::from_low_u64_be(10));

        let mut sub_state_2 = Substate::new();
        sub_state_2
            .contracts_created
            .push(Address::from_low_u64_be(2));
        sub_state_2.logs.push(LogEntry {
            address: Address::from_low_u64_be(1),
            topics: vec![],
            data: vec![],
        });
        sub_state_2.sstore_clears_refund = (15000 * 7).into();

        sub_state.accrue(sub_state_2);
        assert_eq!(sub_state.contracts_created.len(), 2);
        assert_eq!(sub_state.sstore_clears_refund, (15000 * 12).into());
        assert_eq!(sub_state.suicides.len(), 1);
    }
}
