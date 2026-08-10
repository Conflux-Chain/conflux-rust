use cfx_executor::observer::{
    CallTracer, CheckpointTracer, DrainTrace, InternalTransferTracer,
    OpcodeTracer, SetAuthTracer, StorageTracer,
};
use cfx_types::{u256_to_address_be, u256_to_h256_be, Address, H256};
use cfx_vm_interpreter::instructions::Instruction;
use cfx_vm_types::InterpreterInfo;
use primitives::{AccessList, AccessListItem};
use std::collections::{BTreeSet, HashMap, HashSet};
use typemap::ShareDebugMap;

/// An [Inspector] that collects touched accounts and storage slots.
///
/// This can be used to construct an [AccessList] for a transaction via
/// `eth_createAccessList`
#[derive(Debug, Default)]
pub struct AccessListInspector {
    /// All addresses that should be excluded from the final accesslist
    excluded: HashSet<Address>,
    /// All addresses and touched slots
    touched_slots: HashMap<Address, BTreeSet<H256>>,
}

impl From<(AccessList, HashSet<Address>)> for AccessListInspector {
    fn from(data: (AccessList, HashSet<Address>)) -> Self {
        Self::new(data.0, data.1)
    }
}

impl AccessListInspector {
    /// Creates a new [AccessListInspector] with the given excluded addresses.
    pub fn new(access_list: AccessList, excluded: HashSet<Address>) -> Self {
        Self {
            excluded,
            touched_slots: access_list
                .into_iter()
                .map(|v| (v.address, v.storage_keys.into_iter().collect()))
                .collect(),
        }
    }

    /// Returns the excluded addresses.
    pub fn excluded(&self) -> &HashSet<Address> { &self.excluded }

    /// Returns a reference to the map of addresses and their corresponding
    /// touched storage slots.
    pub fn touched_slots(&self) -> &HashMap<Address, BTreeSet<H256>> {
        &self.touched_slots
    }

    /// Consumes the inspector and returns the map of addresses and their
    /// corresponding touched storage slots.
    pub fn into_touched_slots(self) -> HashMap<Address, BTreeSet<H256>> {
        self.touched_slots
    }

    /// Returns list of addresses and storage keys used by the transaction. It
    /// gives you the list of addresses and storage keys that were touched
    /// during execution.
    pub fn into_access_list(self) -> AccessList {
        let items = self.touched_slots.into_iter().map(|(address, slots)| {
            AccessListItem {
                address,
                storage_keys: slots.into_iter().collect(),
            }
        });
        items.collect()
    }

    /// Returns list of addresses and storage keys used by the transaction. It
    /// gives you the list of addresses and storage keys that were touched
    /// during execution.
    pub fn access_list(&self) -> AccessList {
        let items =
            self.touched_slots
                .iter()
                .map(|(address, slots)| AccessListItem {
                    address: *address,
                    storage_keys: slots.iter().copied().collect(),
                });
        items.collect()
    }

    pub fn collect_excluded_addresses(&mut self, item: Address) {
        self.excluded.insert(item);
    }

    /// Marks an address as touched, unless it is one that never belongs in an
    /// access list: the sender, the callee, the precompiles and the 7702
    /// authorities are warm already.
    fn record_address(&mut self, address: Address) {
        if !self.excluded.contains(&address) {
            self.touched_slots.entry(address).or_default();
        }
    }
}

impl DrainTrace for AccessListInspector {
    fn drain_trace(self, map: &mut ShareDebugMap) {
        map.insert::<AccessListKey>(self.into_access_list());
    }
}

pub struct AccessListKey;

impl typemap::Key for AccessListKey {
    type Value = AccessList;
}

impl OpcodeTracer for AccessListInspector {
    fn do_trace_opcode(&self, enabled: &mut bool) { *enabled |= true; }

    fn step(&mut self, interp: &dyn InterpreterInfo) {
        let Some(ins) = Instruction::from_u8(interp.current_opcode()) else {
            return;
        };
        match ins {
            Instruction::SLOAD | Instruction::SSTORE => {
                if let Some(slot) = interp.stack().last() {
                    let cur_contract = interp.contract_address();
                    self.touched_slots
                        .entry(cur_contract)
                        .or_default()
                        .insert(u256_to_h256_be(*slot));
                }
            }
            Instruction::EXTCODECOPY
            | Instruction::EXTCODEHASH
            | Instruction::EXTCODESIZE
            | Instruction::BALANCE
            | Instruction::SUICIDE => {
                let operands = match ins {
                    Instruction::EXTCODECOPY => 4,
                    _ => 1,
                };
                let stack = interp.stack();
                if stack.len() >= operands {
                    // The address is these instructions' first operand, so it
                    // sits on top of the stack.
                    let address = stack[stack.len() - 1];
                    self.record_address(u256_to_address_be(address));
                }
            }
            Instruction::DELEGATECALL
            | Instruction::CALL
            | Instruction::STATICCALL
            | Instruction::CALLCODE => {
                // Every call instruction takes `gas` first and the callee
                // second, so the address sits one below the top of the stack.
                // Requiring the full operand count keeps us off a stack that
                // the instruction itself is about to reject as underflowed.
                let operands = match ins {
                    // gas, address, value, in_off, in_size, out_off, out_size
                    Instruction::CALL | Instruction::CALLCODE => 7,
                    // the same, without `value`
                    _ => 6,
                };
                let stack = interp.stack();
                if stack.len() >= operands {
                    let address = stack[stack.len() - 2];
                    self.record_address(u256_to_address_be(address));
                }
            }
            _ => (),
        }
    }
}

impl CallTracer for AccessListInspector {}
impl CheckpointTracer for AccessListInspector {}
impl InternalTransferTracer for AccessListInspector {}
impl StorageTracer for AccessListInspector {}
impl SetAuthTracer for AccessListInspector {}
