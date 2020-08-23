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
}
