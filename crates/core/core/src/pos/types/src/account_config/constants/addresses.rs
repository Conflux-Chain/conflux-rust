// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::account_address::AccountAddress;

pub use move_core_types::language_storage::CORE_CODE_ADDRESS;

pub fn diem_root_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0xA550C18")
        .expect("Parsing valid hex literal should always succeed")
}

pub fn validator_set_address() -> AccountAddress {
    crate::on_chain_config::config_address()
}

pub fn treasury_compliance_account_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0xB1E55ED")
        .expect("Parsing valid hex literal should always succeed")
}

pub fn reserved_vm_address() -> AccountAddress {
    AccountAddress::new([0u8; AccountAddress::LENGTH])
}

pub fn testnet_dd_account_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0xDD")
        .expect("Parsing valid hex literal should always succeed")
}
