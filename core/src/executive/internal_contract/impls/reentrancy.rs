use cfx_parameters::internal_contract_addresses::ANTI_REENTRANCY_CONTRACT_ADDRESS;
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_statedb::Result as DbResult;
use cfx_types::Address;

pub fn set_reentrancy_allowance(
    contract_address: &Address, allowance: bool, state: &mut dyn StateOpsTrait,
    substate: &mut dyn SubstateTrait, storage_owner: Address,
) -> DbResult<()>
{
    substate.set_storage(
        state,
        &ANTI_REENTRANCY_CONTRACT_ADDRESS,
        contract_address.to_fixed_bytes().into(),
        (allowance as u8).into(),
        storage_owner,
    )
}

pub fn get_reentrancy_allowance(
    contract_address: &Address, state: &mut dyn StateOpsTrait,
    substate: &mut dyn SubstateTrait,
) -> DbResult<bool>
{
    let value = substate.storage_at(
        state,
        &ANTI_REENTRANCY_CONTRACT_ADDRESS,
        contract_address.as_bytes(),
    )?;
    Ok(!value.is_zero())
}
