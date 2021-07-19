// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::CleanupMode;
use crate::evm::{CleanDustMode, Spec};
use cfx_parameters::internal_contract_addresses::ADMIN_CONTROL_CONTRACT_ADDRESS;
use cfx_state::{
    state_trait::StateOpsTrait, substate_trait::SubstateMngTrait, SubstateTrait,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, U256};
use primitives::LogEntry;
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct CallStackInfo {
    call_stack_recipient_addresses: Vec<(Address, bool)>,
    address_counter: HashMap<Address, u32>,
    first_reentrancy_depth: Option<usize>,
}

impl CallStackInfo {
    pub fn new() -> Self {
        CallStackInfo {
            call_stack_recipient_addresses: Vec::default(),
            address_counter: HashMap::default(),
            first_reentrancy_depth: None,
        }
    }

    pub fn push(
        &mut self, address: Address, is_create: bool, allow_reentrancy: bool,
    ) {
        // We should still use the correct behaviour to check if reentrancy
        // happens.
        if !allow_reentrancy
            && self.last() != Some(&address)
            && self.contains_key(&address)
        {
            self.first_reentrancy_depth
                .get_or_insert(self.call_stack_recipient_addresses.len());
        }

        self.call_stack_recipient_addresses
            .push((address.clone(), is_create));
        *self.address_counter.entry(address).or_insert(0) += 1;
    }

    pub fn pop(&mut self) -> Option<(Address, bool)> {
        let maybe_address = self.call_stack_recipient_addresses.pop();
        if let Some((address, _is_create)) = &maybe_address {
            let poped_address_cnt = self
                .address_counter
                .get_mut(address)
                .expect("The lookup table should consistent with call stack");
            *poped_address_cnt -= 1;
            if *poped_address_cnt == 0 {
                self.address_counter.remove(address);
            }
            if self.first_reentrancy_depth
                == Some(self.call_stack_recipient_addresses.len())
            {
                self.first_reentrancy_depth = None
            }
        }
        maybe_address
    }

    pub fn last(&self) -> Option<&Address> {
        self.call_stack_recipient_addresses
            .last()
            .map(|(address, _is_create)| address)
    }

    pub fn contains_key(&self, key: &Address) -> bool {
        self.address_counter.contains_key(key)
    }

    pub fn in_reentrancy(&self, spec: &Spec) -> bool {
        if spec.cip71b {
            // Expected behaviour
            self.first_reentrancy_depth.is_some()
        } else {
            // Consistent with old behaviour
            // The old (unexpected) behaviour is equivalent to the top element
            // is lost.
            self.first_reentrancy_depth.map_or(false, |depth| {
                (depth as isize)
                    < self.call_stack_recipient_addresses.len() as isize - 1
            })
        }
    }

    pub fn contract_in_creation(&self) -> Option<&Address> {
        if let [.., second_last, last] =
            self.call_stack_recipient_addresses.as_slice()
        {
            if last.0 == *ADMIN_CONTROL_CONTRACT_ADDRESS && second_last.1 {
                Some(&second_last.0)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// State changes which should be applied in finalize,
/// after transaction is fully executed.
/// A Substate object is maintained for each contract
/// function instance in the callstack.
#[derive(Debug, Default)]
pub struct Substate {
    /// Any accounts that have suicided.
    pub suicides: HashSet<Address>,
    /// Any accounts that are touched.
    // touched is never used and it is not maintained properly.
    pub touched: HashSet<Address>,
    /// Any accounts that occupy some storage.
    pub storage_collateralized: HashMap<Address, u64>,
    /// Any accounts that release some storage.
    pub storage_released: HashMap<Address, u64>,
    /// Any logs.
    pub logs: Vec<LogEntry>,
    /// Created contracts.
    pub contracts_created: Vec<Address>,
}

impl SubstateMngTrait for Substate {
    fn accrue(&mut self, s: Self) {
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

    fn new() -> Self { Substate::default() }
}

impl SubstateTrait for Substate {
    fn get_collateral_change(&self, address: &Address) -> (u64, u64) {
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

    fn logs(&self) -> &[LogEntry] { &self.logs }

    fn logs_mut(&mut self) -> &mut Vec<LogEntry> { &mut self.logs }

    // Let VM access storage from substate so that storage ownership can be
    // maintained without help from state.
    fn storage_at(
        &self, state: &dyn StateOpsTrait, address: &Address, key: &[u8],
    ) -> DbResult<U256> {
        state.storage_at(address, key)
    }

    // Let VM access storage from substate so that storage ownership can be
    // maintained without help from state.
    fn set_storage(
        &mut self, state: &mut dyn StateOpsTrait, address: &Address,
        key: Vec<u8>, value: U256, owner: Address,
    ) -> DbResult<()>
    {
        state.set_storage(address, key, value, owner)
    }

    fn record_storage_occupy(&mut self, address: &Address, collaterals: u64) {
        *self.storage_collateralized.entry(*address).or_insert(0) +=
            collaterals;
    }

    fn touched(&mut self) -> &mut HashSet<Address> { &mut self.touched }

    fn contracts_created(&self) -> &[Address] { &self.contracts_created }

    fn contracts_created_mut(&mut self) -> &mut Vec<Address> {
        &mut self.contracts_created
    }

    fn record_storage_release(&mut self, address: &Address, collaterals: u64) {
        *self.storage_released.entry(*address).or_insert(0) += collaterals;
    }

    fn keys_for_collateral_changed(&self) -> HashSet<&Address> {
        let affected_address1: HashSet<_> =
            self.storage_collateralized.keys().collect();
        let affected_address2: HashSet<_> =
            self.storage_released.keys().collect();
        affected_address1
            .union(&affected_address2)
            .cloned()
            .collect()
    }

    fn suicides(&self) -> &HashSet<Address> { &self.suicides }

    fn suicides_mut(&mut self) -> &mut HashSet<Address> { &mut self.suicides }
}

/// Get the cleanup mode object from this.
pub fn cleanup_mode<'a>(
    substate: &'a mut dyn SubstateTrait, spec: &Spec,
) -> CleanupMode<'a> {
    match (
        spec.kill_dust != CleanDustMode::Off,
        spec.no_empty,
        spec.kill_empty,
    ) {
        (false, false, _) => CleanupMode::ForceCreate,
        (false, true, false) => CleanupMode::NoEmpty,
        (false, true, true) | (true, _, _) => {
            CleanupMode::TrackTouched(substate.touched())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallStackInfo;
    use crate::state::Substate;
    use cfx_state::substate_trait::SubstateMngTrait;
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

        sub_state.accrue(sub_state_2);
        assert_eq!(sub_state.contracts_created.len(), 2);
        assert_eq!(sub_state.suicides.len(), 1);
    }

    fn get_test_address(n: u8) -> Address { Address::from([n; 20]) }

    #[test]
    fn test_callstack_info() {
        let mut call_stack = CallStackInfo::new();
        call_stack.push(get_test_address(1), false, false);
        call_stack.push(get_test_address(2), false, false);
        assert_eq!(call_stack.pop(), Some((get_test_address(2), false)));
        assert_eq!(call_stack.contains_key(&get_test_address(2)), false);

        call_stack.push(get_test_address(3), true, false);
        call_stack.push(get_test_address(4), false, false);
        call_stack.push(get_test_address(3), false, false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some((get_test_address(3), false)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), true);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(4));

        assert_eq!(call_stack.pop(), Some((get_test_address(4), false)));
        assert_eq!(call_stack.contains_key(&get_test_address(4)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some((get_test_address(3), true)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(1));

        call_stack.push(get_test_address(3), true, false);
        call_stack.push(get_test_address(4), false, false);
        call_stack.push(get_test_address(3), false, false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some((get_test_address(3), false)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), true);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(4));

        assert_eq!(call_stack.pop(), Some((get_test_address(4), false)));
        assert_eq!(call_stack.contains_key(&get_test_address(4)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some((get_test_address(3), true)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(1));

        assert_eq!(call_stack.pop(), Some((get_test_address(1), false)));
        assert_eq!(call_stack.pop(), None);
        assert_eq!(call_stack.last(), None);
    }
}
