use super::macros::*;
use crate::vm::Spec;
use cfx_parameters::internal_contract_addresses::*;
use cfx_types::Address;

// Set the internal contract addresses to be activated in the future. So we can
// update the hardcoded test mode genesis state  without waiting for the
// implementation of each contract.
make_solidity_contract! {
    pub(super) struct AntiReentrancy(ANTI_REENTRANCY_CONTRACT_ADDRESS, "placeholder");
}
make_solidity_contract! {
    pub(super) struct PoS(POS_REGISTER_CONTRACT_ADDRESS, "placeholder");
}
