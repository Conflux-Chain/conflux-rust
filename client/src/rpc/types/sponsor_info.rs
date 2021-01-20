// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::Address as Base32Address;
use cfx_addr::Network;
use cfx_types::U256;
use primitives::SponsorInfo as PrimitiveSponsorInfo;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SponsorInfo {
    /// This is the address of the sponsor for gas cost of the contract.
    pub sponsor_for_gas: Base32Address,
    /// This is the address of the sponsor for collateral of the contract.
    pub sponsor_for_collateral: Base32Address,
    /// This is the upper bound of sponsor gas cost per tx.
    pub sponsor_gas_bound: U256,
    /// This is the amount of tokens sponsor for gas cost to the contract.
    pub sponsor_balance_for_gas: U256,
    /// This is the amount of tokens sponsor for collateral to the contract.
    pub sponsor_balance_for_collateral: U256,
}

impl SponsorInfo {
    pub fn default(network: Network) -> Result<Self, String> {
        Ok(Self {
            sponsor_for_gas: Base32Address::null(network)?,
            sponsor_for_collateral: Base32Address::null(network)?,
            sponsor_gas_bound: Default::default(),
            sponsor_balance_for_gas: Default::default(),
            sponsor_balance_for_collateral: Default::default(),
        })
    }

    pub fn try_from(
        sponsor_info: PrimitiveSponsorInfo, network: Network,
    ) -> Result<Self, String> {
        Ok(Self {
            sponsor_for_gas: Base32Address::try_from_h160(
                sponsor_info.sponsor_for_gas,
                network,
            )?,
            sponsor_for_collateral: Base32Address::try_from_h160(
                sponsor_info.sponsor_for_collateral,
                network,
            )?,
            sponsor_gas_bound: sponsor_info.sponsor_gas_bound,
            sponsor_balance_for_gas: sponsor_info.sponsor_balance_for_gas,
            sponsor_balance_for_collateral: sponsor_info
                .sponsor_balance_for_collateral,
        })
    }
}
