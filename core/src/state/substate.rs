// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::CleanupMode;
use crate::evm::{CleanDustMode, Spec};
use cfx_types::Address;
use primitives::LogEntry;
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    rc::Rc,
};

#[derive(Debug, Default)]
pub struct CallStackInfo {
    call_stack_recipient_addresses: Vec<Address>,
    address_counter: HashMap<Address, u32>,
}

impl CallStackInfo {
    fn push(&mut self, address: Address) {
        self.call_stack_recipient_addresses.push(address.clone());
        *self.address_counter.entry(address).or_insert(0) += 1;
    }

    fn pop(&mut self) -> Option<Address> {
        let maybe_address = self.call_stack_recipient_addresses.pop();
        if let Some(address) = &maybe_address {
            let poped_address_cnt = self
                .address_counter
                .get_mut(address)
                .expect("The lookup table should consistent with call stack");
            *poped_address_cnt -= 1;
            if *poped_address_cnt == 0 {
                self.address_counter.remove(address);
            }
        }
        maybe_address
    }

    pub fn last(&self) -> Option<&Address> {
        self.call_stack_recipient_addresses.last()
    }

    pub fn contains_key(&self, key: &Address) -> bool {
        self.address_counter.contains_key(key)
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
    pub touched: HashSet<Address>,
    /// Any accounts that occupy some storage.
    pub storage_collateralized: HashMap<Address, u64>,
    /// Any accounts that release some storage.
    pub storage_released: HashMap<Address, u64>,
    /// Any logs.
    pub logs: Vec<LogEntry>,
    /// Refund counter of SSTORE.
    pub sstore_clears_refund: i128,
    /// Created contracts.
    pub contracts_created: Vec<Address>,

    /// The following two variables are parts in call params.
    /// (Parameters in spec other than Params struct in code)
    /// We implement them in substate for performance.
    /// So they are not considered in accruing substate and
    /// must be maintained carefully.

    /// Contracts called in call stack.
    /// Used to detect reentrancy.
    /// Passed from caller to callee when calling happens
    /// and passed back to caller when callee returns,
    /// through mem::swap.
    pub contracts_in_callstack: Rc<RefCell<CallStackInfo>>,
}

impl Substate {
    /// Creates new substate.
    pub fn new() -> Self { Substate::default() }

    pub fn with_call_stack(callstack: Rc<RefCell<CallStackInfo>>) -> Self {
        let mut substate = Substate::default();
        substate.contracts_in_callstack = callstack;
        substate
    }

    pub fn push_callstack(&self, contract: Address) {
        self.contracts_in_callstack.borrow_mut().push(contract);
    }

    #[inline]
    pub fn pop_callstack(&self) {
        self.contracts_in_callstack.borrow_mut().pop();
    }

    /// Merge secondary substate `s` into self, accruing each element
    /// correspondingly.
    pub fn accrue(&mut self, s: Substate) {
        self.suicides.extend(s.suicides);
        self.touched.extend(s.touched);
        self.logs.extend(s.logs);
        self.sstore_clears_refund += s.sstore_clears_refund;
        self.contracts_created.extend(s.contracts_created);
        for (address, amount) in s.storage_collateralized {
            *self.storage_collateralized.entry(address).or_insert(0) += amount;
        }
        for (address, amount) in s.storage_released {
            *self.storage_released.entry(address).or_insert(0) += amount;
        }
    }

    pub fn record_storage_occupy(&mut self, address: &Address, amount: u64) {
        *self.storage_collateralized.entry(*address).or_insert(0) += amount;
    }

    pub fn record_storage_release(&mut self, address: &Address, amount: u64) {
        *self.storage_released.entry(*address).or_insert(0) += amount;
    }

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

#[cfg(test)]
mod tests {
    use super::{CallStackInfo, Substate};
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

    fn get_test_address(n: u8) -> Address { Address::from([n; 20]) }

    #[test]
    fn test_callstack_info() {
        let mut call_stack = CallStackInfo::default();
        call_stack.push(get_test_address(1));
        call_stack.push(get_test_address(2));
        assert_eq!(call_stack.pop(), Some(get_test_address(2)));
        assert_eq!(call_stack.contains_key(&get_test_address(2)), false);

        call_stack.push(get_test_address(3));
        call_stack.push(get_test_address(4));
        call_stack.push(get_test_address(3));
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some(get_test_address(3)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), true);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(4));

        assert_eq!(call_stack.pop(), Some(get_test_address(4)));
        assert_eq!(call_stack.contains_key(&get_test_address(4)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some(get_test_address(3)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(1));

        call_stack.push(get_test_address(3));
        call_stack.push(get_test_address(4));
        call_stack.push(get_test_address(3));
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some(get_test_address(3)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), true);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(4));

        assert_eq!(call_stack.pop(), Some(get_test_address(4)));
        assert_eq!(call_stack.contains_key(&get_test_address(4)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(3));

        assert_eq!(call_stack.pop(), Some(get_test_address(3)));
        assert_eq!(call_stack.contains_key(&get_test_address(3)), false);
        assert_eq!(call_stack.last().unwrap().clone(), get_test_address(1));

        assert_eq!(call_stack.pop(), Some(get_test_address(1)));
        assert_eq!(call_stack.pop(), None);
        assert_eq!(call_stack.last(), None);
    }
}
