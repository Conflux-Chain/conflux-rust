// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::state::CleanupMode;
use cfx_types::{Address, AddressWithSpace};
use cfx_vm_types::{CleanDustMode, Spec};
use primitives::{
    receipt::{SortedStorageChanges, StorageChange},
    LogEntry,
};
use std::collections::{HashMap, HashSet};

/// Tracks execution changes for the post-execution process in the executive,
/// such as charging collateral, generating receipt, and recycling killed
/// contracts.
#[derive(Debug, Default)]
pub struct Substate {
    /// Any accounts that have suicided.
    pub suicides: HashSet<AddressWithSpace>,
    /// Any accounts that are touched.
    // touched is never used and it is not maintained properly.
    pub touched: HashSet<AddressWithSpace>,
    /// Any accounts that occupy some storage.
    pub storage_collateralized: HashMap<Address, u64>,
    /// Any accounts that release some storage.
    pub storage_released: HashMap<Address, u64>,
    /// Any logs.
    pub logs: Vec<LogEntry>,
    /// Created contracts.
    pub contracts_created: Vec<AddressWithSpace>,
}

impl Substate {
    pub fn accrue(&mut self, s: Self) {
        self.suicides.extend(s.suicides);
        self.touched.extend(s.touched);
        self.logs.extend(s.logs);
        self.contracts_created.extend(s.contracts_created);
        for (address, amount) in s.storage_collateralized {
            *self.storage_collateralized.entry(address).or_insert(0) += amount;
        }
        for (address, amount) in s.storage_released {
            *self.storage_released.entry(address).or_insert(0) += amount;
        }
    }

    pub fn new() -> Self { Substate::default() }
}

impl Substate {
    pub fn get_collateral_change(&self, address: &Address) -> (u64, u64) {
        let inc = self
            .storage_collateralized
            .get(address)
            .cloned()
            .unwrap_or(0);
        let sub = self.storage_released.get(address).cloned().unwrap_or(0);
        if inc > sub {
            (inc - sub, 0)
        } else {
            (0, sub - inc)
        }
    }

    pub fn compute_storage_changes(&self) -> SortedStorageChanges {
        let mut storage_collateralized = vec![];
        let mut storage_released = vec![];

        let mut affected_address: Vec<_> =
            self.keys_for_collateral_changed().iter().cloned().collect();
        affected_address.sort();
        for address in affected_address {
            let (inc, sub) = self.get_collateral_change(&address);
            if inc > 0 {
                storage_collateralized.push(StorageChange {
                    address: *address,
                    collaterals: inc.into(),
                });
            } else if sub > 0 {
                storage_released.push(StorageChange {
                    address: *address,
                    collaterals: sub.into(),
                });
            }
        }
        SortedStorageChanges {
            storage_collateralized,
            storage_released,
        }
    }

    pub fn record_storage_occupy(
        &mut self, address: &Address, collaterals: u64,
    ) {
        *self.storage_collateralized.entry(*address).or_insert(0) +=
            collaterals;
    }

    pub fn record_storage_release(
        &mut self, address: &Address, collaterals: u64,
    ) {
        *self.storage_released.entry(*address).or_insert(0) += collaterals;
    }

    pub fn keys_for_collateral_changed(&self) -> HashSet<&Address> {
        let affected_address1: HashSet<_> =
            self.storage_collateralized.keys().collect();
        let affected_address2: HashSet<_> =
            self.storage_released.keys().collect();
        affected_address1
            .union(&affected_address2)
            .cloned()
            .collect()
    }
}

/// Get the cleanup mode object from this.
pub fn cleanup_mode<'a>(
    substate: &'a mut Substate, spec: &Spec,
) -> CleanupMode<'a> {
    match (
        spec.kill_dust != CleanDustMode::Off,
        spec.no_empty,
        spec.kill_empty,
    ) {
        (false, false, _) => CleanupMode::ForceCreate,
        (false, true, false) => CleanupMode::NoEmpty,
        (false, true, true) | (true, _, _) => {
            CleanupMode::TrackTouched(&mut substate.touched)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Substate;
    use cfx_types::{Address, AddressSpaceUtil, Space};
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
            .push(Address::from_low_u64_be(1).with_native_space());
        sub_state.logs.push(LogEntry {
            address: Address::from_low_u64_be(1),
            topics: vec![],
            data: vec![],
            space: Space::Native,
        });
        sub_state
            .suicides
            .insert(Address::from_low_u64_be(10).with_native_space());

        let mut sub_state_2 = Substate::new();
        sub_state_2
            .contracts_created
            .push(Address::from_low_u64_be(2).with_native_space());
        sub_state_2.logs.push(LogEntry {
            address: Address::from_low_u64_be(1),
            topics: vec![],
            data: vec![],
            space: Space::Native,
        });

        sub_state.accrue(sub_state_2);
        assert_eq!(sub_state.contracts_created.len(), 2);
        assert_eq!(sub_state.suicides.len(), 1);
    }
}
