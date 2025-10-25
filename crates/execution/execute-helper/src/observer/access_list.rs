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

    pub fn collcect_excluded_addresses(&mut self, item: Address) {
        self.excluded.insert(item);
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
    fn step(&mut self, interp: &dyn InterpreterInfo) {
        let ins = Instruction::from_u8(interp.current_opcode())
            .expect("invalid opcode");
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
                if let Some(slot) = interp.stack().last() {
                    let addr = u256_to_address_be(*slot);
                    if !self.excluded.contains(&addr) {
                        self.touched_slots.entry(addr).or_default();
                    }
                }
            }
            Instruction::DELEGATECALL
            | Instruction::CALL
            | Instruction::STATICCALL
            | Instruction::CALLCODE => {
                if let Some(slot) = interp.stack().last() {
                    let addr = u256_to_address_be(*slot);
                    if !self.excluded.contains(&addr) {
                        self.touched_slots.entry(addr).or_default();
                    }
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
