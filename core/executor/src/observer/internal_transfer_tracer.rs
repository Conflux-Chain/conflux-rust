use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, U256,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

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

    fn trace_convert_stroage_points(
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressPocket {
    Balance(AddressWithSpace),
    StakingBalance(Address),
    StorageCollateral(Address),
    SponsorBalanceForGas(Address),
    SponsorBalanceForStorage(Address),
    MintBurn,
    GasPayment,
}

impl AddressPocket {
    pub fn inner_address(&self) -> Option<&Address> {
        use AddressPocket::*;
        match self {
            Balance(AddressWithSpace { address: addr, .. })
            | StakingBalance(addr)
            | StorageCollateral(addr)
            | SponsorBalanceForGas(addr)
            | SponsorBalanceForStorage(addr) => Some(addr),
            MintBurn | GasPayment => None,
        }
    }

    pub fn inner_address_or_default(&self) -> Address {
        self.inner_address().cloned().unwrap_or(Address::zero())
    }

    pub fn pocket(&self) -> &'static str {
        use AddressPocket::*;
        match self {
            Balance(_) => "balance",
            StakingBalance(_) => "staking_balance",
            StorageCollateral(_) => "storage_collateral",
            SponsorBalanceForGas(_) => "sponsor_balance_for_gas",
            SponsorBalanceForStorage(_) => "sponsor_balance_for_collateral",
            MintBurn => "mint_or_burn",
            GasPayment => "gas_payment",
        }
    }

    pub fn space(&self) -> &'static str {
        use AddressPocket::*;
        match self {
            Balance(AddressWithSpace { space, .. }) => space.clone().into(),
            MintBurn | GasPayment => "none",
            _ => Space::Native.into(),
        }
    }

    fn type_number(&self) -> u8 {
        use AddressPocket::*;
        match self {
            Balance(AddressWithSpace {
                space: Space::Native,
                ..
            }) => 0,
            StakingBalance(_) => 1,
            StorageCollateral(_) => 2,
            SponsorBalanceForGas(_) => 3,
            SponsorBalanceForStorage(_) => 4,
            MintBurn => 5,
            GasPayment => 6,
            Balance(AddressWithSpace {
                space: Space::Ethereum,
                ..
            }) => 7,
        }
    }
}

impl Encodable for AddressPocket {
    fn rlp_append(&self, s: &mut RlpStream) {
        let maybe_address = self.inner_address();
        let type_number = self.type_number();
        if let Some(address) = maybe_address {
            s.begin_list(2);
            s.append(&type_number);
            s.append(address);
        } else {
            s.begin_list(1);
            s.append(&type_number);
        }
    }
}

impl Decodable for AddressPocket {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        use AddressPocket::*;

        let type_number: u8 = rlp.val_at(0)?;
        match type_number {
            0 => rlp
                .val_at(1)
                .map(|addr: Address| Balance(addr.with_native_space())),
            1 => rlp.val_at(1).map(StakingBalance),
            2 => rlp.val_at(1).map(StorageCollateral),
            3 => rlp.val_at(1).map(SponsorBalanceForGas),
            4 => rlp.val_at(1).map(SponsorBalanceForStorage),
            5 => Ok(MintBurn),
            6 => Ok(GasPayment),
            7 => rlp
                .val_at(1)
                .map(|addr: Address| Balance(addr.with_evm_space())),
            _ => {
                Err(DecoderError::Custom("Invalid internal transfer address."))
            }
        }
    }
}
