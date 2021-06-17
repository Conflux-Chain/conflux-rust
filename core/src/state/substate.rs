// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::CleanupMode;
use crate::evm::{CleanDustMode, Spec};
use cfx_state::{
    state_trait::StateOpsTrait, substate_trait::SubstateMngTrait, SubstateTrait,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, U256};
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
    first_reentrancy_depth: Option<usize>,
}

impl CallStackInfo {
    fn push(&mut self, address: Address) {
        if self.reentrancy_happens_when_push(&address) {
            self.first_reentrancy_depth
                .get_or_insert(self.call_stack_recipient_addresses.len());
        }

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
            if self.first_reentrancy_depth
                == Some(self.call_stack_recipient_addresses.len())
            {
                self.first_reentrancy_depth = None
            }
        }
        maybe_address
    }

    pub fn reentrancy_happens_when_push(&self, address: &Address) -> bool {
        self.last() != Some(address) && self.contains_key(address)
    }

    pub fn last(&self) -> Option<&Address> {
        self.call_stack_recipient_addresses.last()
    }

    pub fn contains_key(&self, key: &Address) -> bool {
        self.address_counter.contains_key(key)
    }

    pub fn in_reentrancy(&self) -> bool {
        self.first_reentrancy_depth.is_some()
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
    /// The contract which is being constructed. The contract address is set at
    /// the beginning of the constructor. When an internal contract is called
    /// from the contract constructor, the contract_in_creation is inherited
    /// from the constructor as the contract address.
    /// The contract address is set to None when calling a normal account.
    /// When a new contract constructor is called, the contract_in_creation
    /// address is set to the new contract address.
    contract_in_creation: Option<Address>,
}

impl SubstateMngTrait for Substate {
    fn with_call_stack(callstack: Rc<RefCell<Self::CallStackInfo>>) -> Self {
        let mut substate = Substate::default();
        substate.contracts_in_callstack = callstack;
        substate
    }

    fn accrue(&mut self, s: Self) {
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

    fn new() -> Self { Substate::default() }

    fn update_contract_in_creation_call(
        mut self, parent_contract_in_creation: Option<Address>,
        is_internal_contract: bool,
    ) -> Self
    {
        debug!(
            "update_contract_in_creation_call {:?}, is_internal_contract {}",
            parent_contract_in_creation, is_internal_contract
        );
        if is_internal_contract {
            self.contract_in_creation = parent_contract_in_creation;
        } else {
            self.contract_in_creation = None;
        }

        self
    }

    fn set_contract_in_creation_create(
        mut self, contract_in_creation: Address,
    ) -> Self {
        debug!("set_contract_in_creation_call {:?}", contract_in_creation);
        self.contract_in_creation = Some(contract_in_creation);
        self
    }
}

impl SubstateTrait for Substate {
    type CallStackInfo = CallStackInfo;
    type Spec = Spec;

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

    /// Get the cleanup mode object from this.
    fn to_cleanup_mode(&mut self, spec: &Spec) -> CleanupMode {
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

    fn pop_callstack(&self) { self.contracts_in_callstack.borrow_mut().pop(); }

    fn push_callstack(&self, contract: Address) {
        self.contracts_in_callstack.borrow_mut().push(contract);
    }

    fn contracts_in_callstack(&self) -> &Rc<RefCell<CallStackInfo>> {
        &self.contracts_in_callstack
    }

    fn in_reentrancy(&self) -> bool {
        self.contracts_in_callstack
            .borrow()
            .first_reentrancy_depth
            .is_some()
    }

    fn sstore_clears_refund(&self) -> i128 { self.sstore_clears_refund }

    fn sstore_clears_refund_mut(&mut self) -> &mut i128 {
        &mut self.sstore_clears_refund
    }

    fn contracts_created(&self) -> &[Address] { &self.contracts_created }

    fn contracts_created_mut(&mut self) -> &mut Vec<Address> {
        &mut self.contracts_created
    }

    fn reentrancy_happens_when_push(&self, address: &Address) -> bool {
        self.contracts_in_callstack
            .borrow()
            .call_stack_recipient_addresses
            .last()
            != Some(address)
            && self.contains_key(address)
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

    fn contains_key(&self, key: &Address) -> bool {
        self.contracts_in_callstack
            .borrow()
            .address_counter
            .contains_key(key)
    }

    fn suicides(&self) -> &HashSet<Address> { &self.suicides }

    fn suicides_mut(&mut self) -> &mut HashSet<Address> { &mut self.suicides }

    fn contract_in_creation(&self) -> Option<&Address> {
        debug!("contract_in_creation {:?}", self.contract_in_creation);
        self.contract_in_creation.as_ref()
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
