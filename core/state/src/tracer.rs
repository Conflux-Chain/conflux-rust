// The tracer should not be here. But StateTrait expose too much details about
// VM execution. So I have to move the definition of state parameters here.
// I don't know why we have such a trait, which define almost all the
// implementation details of state access as trait functions.

use cfx_types::{Address, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// This trait is used by executive to build traces.
pub trait InternalTransferTracer: Send {
    /// Prepares internal transfer action
    fn prepare_internal_transfer_action(
        &mut self, from: AddressPocket, to: AddressPocket, value: U256,
    );
}

#[derive(Debug, Clone, PartialEq)]
pub enum AddressPocket {
    Balance(Address),
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
            Balance(addr)
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

    fn type_number(&self) -> u8 {
        use AddressPocket::*;
        match self {
            Balance(_) => 0,
            StakingBalance(_) => 1,
            StorageCollateral(_) => 2,
            SponsorBalanceForGas(_) => 3,
            SponsorBalanceForStorage(_) => 4,
            MintBurn => 5,
            GasPayment => 6,
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
            0 => rlp.val_at(1).map(Balance),
            1 => rlp.val_at(1).map(StakingBalance),
            2 => rlp.val_at(1).map(StorageCollateral),
            3 => rlp.val_at(1).map(SponsorBalanceForGas),
            4 => rlp.val_at(1).map(SponsorBalanceForStorage),
            5 => Ok(MintBurn),
            6 => Ok(GasPayment),
            _ => {
                Err(DecoderError::Custom("Invalid internal transfer address."))
            }
        }
    }
}
