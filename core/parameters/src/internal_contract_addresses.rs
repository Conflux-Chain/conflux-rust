// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::Address;
use std::str::FromStr;

lazy_static! {
    pub static ref ADMIN_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000000").unwrap();
    pub static ref SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000001").unwrap();
    pub static ref STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000002").unwrap();

    pub static ref CONTEXT_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000004").unwrap();
    pub static ref POS_REGISTER_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000005").unwrap();
    pub static ref CROSS_SPACE_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000006").unwrap();
    pub static ref PARAMS_CONTROL_CONTRACT_ADDRESS: Address =
        Address::from_str("0888000000000000000000000000000000000007").unwrap();
    pub static ref SYSTEM_STORAGE_ADDRESS: Address =
        Address::from_str("088800000000000000000000000000000000000a").unwrap();

    // We reserve more addresses so we don't need to change the genesis hash
    // in test mode each time adding new internal contracts.
    pub static ref RESERVED3: Address =
        Address::from_str("0888000000000000000000000000000000000003").unwrap();
    pub static ref RESERVED8: Address =
        Address::from_str("0888000000000000000000000000000000000008").unwrap();
    pub static ref RESERVED9: Address =
        Address::from_str("0888000000000000000000000000000000000009").unwrap();
    pub static ref RESERVED11: Address =
        Address::from_str("088800000000000000000000000000000000000b").unwrap();
}
