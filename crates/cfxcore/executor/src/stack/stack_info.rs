use cfx_parameters::internal_contract_addresses::ADMIN_CONTROL_CONTRACT_ADDRESS;
use cfx_types::{AddressSpaceUtil, AddressWithSpace};
use cfx_vm_types::Spec;
use std::collections::HashMap;

#[derive(Debug)]
pub struct CallStackInfo {
    call_stack_recipient_addresses: Vec<(AddressWithSpace, bool)>,
    address_counter: HashMap<AddressWithSpace, u32>,
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

    pub fn push(&mut self, address: AddressWithSpace, is_create: bool) {
        // We should still use the correct behaviour to check if reentrancy
        // happens.
        if self.last() != Some(&address) && self.contains_key(&address) {
            self.first_reentrancy_depth
                .get_or_insert(self.call_stack_recipient_addresses.len());
        }

        self.call_stack_recipient_addresses
            .push((address.clone(), is_create));
        *self.address_counter.entry(address).or_insert(0) += 1;
    }

    pub fn pop(&mut self) -> Option<(AddressWithSpace, bool)> {
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

    pub fn last(&self) -> Option<&AddressWithSpace> {
        self.call_stack_recipient_addresses
            .last()
            .map(|(address, _is_create)| address)
    }

    pub fn contains_key(&self, key: &AddressWithSpace) -> bool {
        self.address_counter.contains_key(key)
    }

    pub fn in_reentrancy(&self, spec: &Spec) -> bool {
        if spec.cip71 {
            // After CIP-71, anti-reentrancy will closed.
            false
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

    pub fn contract_in_creation(&self) -> Option<&AddressWithSpace> {
        if let [.., second_last, last] =
            self.call_stack_recipient_addresses.as_slice()
        {
            if last.0 == ADMIN_CONTROL_CONTRACT_ADDRESS.with_native_space()
                && second_last.1
            {
                Some(&second_last.0)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CallStackInfo;
    use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace};

    fn get_test_address_raw(n: u8) -> Address { Address::from([n; 20]) }

    fn get_test_address(n: u8) -> AddressWithSpace {
        get_test_address_raw(n).with_native_space()
    }

    #[test]
    fn test_callstack_info() {
        let mut call_stack = CallStackInfo::new();
        call_stack.push(get_test_address(1), false);
        call_stack.push(get_test_address(2), false);
        assert_eq!(call_stack.pop(), Some((get_test_address(2), false)));
        assert_eq!(call_stack.contains_key(&get_test_address(2)), false);

        call_stack.push(get_test_address(3), true);
        call_stack.push(get_test_address(4), false);
        call_stack.push(get_test_address(3), false);
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

        call_stack.push(get_test_address(3), true);
        call_stack.push(get_test_address(4), false);
        call_stack.push(get_test_address(3), false);
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
