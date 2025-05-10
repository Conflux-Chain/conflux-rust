use cfx_parity_trace_types::AddressPocket;
use cfx_types::{address_util::AddressUtil, Address, AddressSpaceUtil, U256};

use self::AddressPocket::*;

use impl_tools::autoimpl;
use impl_trait_for_tuples::impl_for_tuples;

#[impl_for_tuples(3)]
#[autoimpl(for<T: trait + ?Sized> &mut T)]
#[allow(unused_variables)]
/// This trait is used by executive to build traces.
pub trait InternalTransferTracer {
    /// Prepares internal transfer action
    fn trace_internal_transfer(
        &mut self, from: AddressPocket, to: AddressPocket, value: U256,
    ) {
    }

    fn trace_convert_storage_points(
        &mut self, addr: Address, from_balance: U256, from_collateral: U256,
    ) {
        if !from_balance.is_zero() {
            self.trace_internal_transfer(
                SponsorBalanceForStorage(addr),
                MintBurn,
                from_balance,
            );
        }
        if !from_collateral.is_zero() {
            self.trace_internal_transfer(
                StorageCollateral(addr),
                MintBurn,
                from_collateral,
            );
        }
    }

    fn trace_refund_collateral(&mut self, addr: Address, by: U256) {
        if !by.is_zero() {
            self.trace_internal_transfer(
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

    fn trace_occupy_collateral(&mut self, addr: Address, by: U256) {
        if !by.is_zero() {
            self.trace_internal_transfer(
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
}
