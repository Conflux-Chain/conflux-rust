// The tracer should not be here. But StateTrait expose too much details about
// VM execution. So I have to move the definition of state parameters here.
// I don't know why we have such a trait, which define almost all the
// implementation details of state access as trait functions.

use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// This trait is used by executive to build traces.
pub trait StateTracer: Send {
    /// Prepares internal transfer action
    fn trace_internal_transfer(
        &mut self, from: AddressPocket, to: AddressPocket, value: U256,
    );

    /// Make a checkpoint for validity mark
    fn checkpoint(&mut self);

    /// Discard the top checkpoint for validity mark
    fn discard_checkpoint(&mut self);

    /// Mark the traces to the top checkpoint as "valid = false"
    fn revert_to_checkpoint(&mut self);
}

impl StateTracer for () {
    fn trace_internal_transfer(
        &mut self, _: AddressPocket, _: AddressPocket, _: U256,
    ) {
    }

    fn checkpoint(&mut self) {}

    fn discard_checkpoint(&mut self) {}

    fn revert_to_checkpoint(&mut self) {}
}

impl<T> StateTracer for &mut T
where T: StateTracer
{
    fn trace_internal_transfer(
        &mut self, from: AddressPocket, to: AddressPocket, value: U256,
    ) {
        (*self).trace_internal_transfer(from, to, value);
    }

    fn checkpoint(&mut self) { (*self).checkpoint(); }

    fn discard_checkpoint(&mut self) { (*self).discard_checkpoint(); }

    fn revert_to_checkpoint(&mut self) { (*self).revert_to_checkpoint(); }
}

impl<S, T> StateTracer for (&mut S, &mut T)
where
    S: StateTracer,
    T: StateTracer,
{
    fn trace_internal_transfer(
        &mut self, from: AddressPocket, to: AddressPocket, value: U256,
    ) {
        self.0.trace_internal_transfer(from, to, value);
        self.1.trace_internal_transfer(from, to, value);
    }

    fn checkpoint(&mut self) {
        self.0.checkpoint();
        self.1.checkpoint();
    }

    fn discard_checkpoint(&mut self) {
        self.0.discard_checkpoint();
        self.1.discard_checkpoint();
    }

    fn revert_to_checkpoint(&mut self) {
        self.0.revert_to_checkpoint();
        self.1.revert_to_checkpoint();
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
