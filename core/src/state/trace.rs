use cfx_state::tracer::{AddressPocket::*, StateTracer};
use cfx_types::{address_util::AddressUtil, Address, AddressSpaceUtil, U256};

pub fn trace_convert_stroage_points(
    tracer: &mut dyn StateTracer, addr: Address, from_balance: U256,
    from_collateral: U256,
)
{
    if !from_balance.is_zero() {
        tracer.trace_internal_transfer(
            SponsorBalanceForStorage(addr),
            MintBurn,
            from_balance,
        );
    }
    if !from_collateral.is_zero() {
        tracer.trace_internal_transfer(
            StorageCollateral(addr),
            MintBurn,
            from_collateral,
        );
    }
}

pub fn trace_refund_collateral(
    tracer: &mut dyn StateTracer, addr: Address, by: U256,
) {
    if !by.is_zero() {
        tracer.trace_internal_transfer(
            StorageCollateral(addr),
            if addr.is_contract_address() {
                SponsorBalanceForStorage(addr)
            } else {
                Balance(addr.with_native_space())
            },
            by,
        );
    }
}

pub fn trace_occupy_collateral(
    tracer: &mut dyn StateTracer, addr: Address, by: U256,
) {
    if !by.is_zero() {
        tracer.trace_internal_transfer(
            if addr.is_contract_address() {
                SponsorBalanceForStorage(addr)
            } else {
                Balance(addr.with_native_space())
            },
            StorageCollateral(addr),
            by,
        );
    }
}
