use super::{macros::*, SolFnTable};
use crate::vm::Spec;
use cfx_parameters::internal_contract_addresses::*;
use cfx_types::Address;

// Set the internal contract addresses to be activated in the future. So we can
// update the hardcoded test mode genesis state  without waiting for the
// implementation of each contract.
make_solidity_contract! {
    pub(super) struct AntiReentrancyConfig(ANTI_REENTRANCY_CONTRACT_ADDRESS, "placeholder");
}

// The internal contract for storing system information without storage owner.
// Instantiation this contract when cip-94 is ready.
make_solidity_contract! {
    pub(super) struct SystemStorage(SYSTEM_STORAGE_ADDRESS, "placeholder");
}

make_solidity_contract! {
    pub(super) struct Reserved8(RESERVED8, "placeholder");
}
make_solidity_contract! {
    pub(super) struct Reserved9(RESERVED9, "placeholder");
}
make_solidity_contract! {
    pub(super) struct Reserved11(RESERVED11, "placeholder");
}
