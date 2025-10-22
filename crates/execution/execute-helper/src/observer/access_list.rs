use cfx_executor::{
    observer::{
        CallTracer, CheckpointTracer, DrainTrace, InternalTransferTracer,
        OpcodeTracer, SetAuthTracer, StorageTracer,
    },
    stack::FrameResult,
};
use cfx_types::{
    cal_contract_address, u256_to_address_be, u256_to_h256_be, Address,
    AddressUtil, CreateContractAddressType, Space, H256, U256,
};
use cfx_vm_interpreter::instructions::Instruction;
use cfx_vm_types::{ActionParams, InterpreterInfo};
use primitives::{AccessList, AccessListItem};
use std::collections::{BTreeSet, HashMap, HashSet};

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

    depth: usize,
}

impl From<AccessList> for AccessListInspector {
    fn from(access_list: AccessList) -> Self { Self::new(access_list) }
}

impl AccessListInspector {
    /// Creates a new [AccessListInspector] with the given excluded addresses.
    pub fn new(access_list: AccessList) -> Self {
        Self {
            excluded: Default::default(),
            touched_slots: access_list
                .into_iter()
                .map(|v| (v.address, v.storage_keys.into_iter().collect()))
                .collect(),
            depth: 0,
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

    fn collcect_excluded_addresses(&mut self, item: Address) {
        self.excluded.insert(item);
    }
}

impl CallTracer for AccessListInspector {
    fn record_call(&mut self, params: &ActionParams) {
        if self.depth == 0 {
            self.collcect_excluded_addresses(params.original_sender);
            self.collcect_excluded_addresses(params.address);
            // TODO 7702 authorities should be excluded because those get loaded
            // anyway
        }
        self.depth += 1;
    }

    fn record_call_result(&mut self, _result: &FrameResult) { self.depth -= 1; }

    fn record_create(&mut self, params: &ActionParams) {
        if self.depth == 0 {
            let from = params.original_sender;

            // add caller to excluded list
            self.collcect_excluded_addresses(from);

            // add created address to excluded list
            let create_type = match params.space {
                Space::Native => {
                    CreateContractAddressType::FromSenderNonceAndCodeHash
                }
                Space::Ethereum => CreateContractAddressType::FromSenderNonce,
            };
            let nonce = U256::from(0); // TODO get nonce from state
            let empty_code = Vec::new();
            let code = params.code.as_deref().unwrap_or(&empty_code); // TODO check code is right here
            let (mut created_address, _) =
                cal_contract_address(create_type, 0, &from, &nonce, code);
            if params.space == Space::Native {
                created_address.set_contract_type_bits();
            }
            self.collcect_excluded_addresses(created_address);
        }
        self.depth += 1;
    }

    fn record_create_result(&mut self, _result: &FrameResult) {
        self.depth -= 1;
    }
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

impl CheckpointTracer for AccessListInspector {}
impl InternalTransferTracer for AccessListInspector {}
impl StorageTracer for AccessListInspector {}
impl SetAuthTracer for AccessListInspector {}
