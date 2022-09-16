// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Cost spec and other parameterisations for the EVM.

use crate::spec::CommonParams;
use cfx_parameters::consensus_internal::DAO_PARAMETER_VOTE_PERIOD;
use cfx_types::{address_util::AddressUtil, Address, U256};
use primitives::BlockNumber;

/// Definition of the cost spec and other parameterisations for the VM.
#[derive(Debug, Clone)]
pub struct Spec {
    /// Does it support exceptional failed code deposit
    pub exceptional_failed_code_deposit: bool,
    /// VM stack limit
    pub stack_limit: usize,
    /// Max number of nested calls/creates
    pub max_depth: usize,
    /// Gas prices for instructions in all tiers
    pub tier_step_gas: [usize; 8],
    /// Gas price for `EXP` opcode
    pub exp_gas: usize,
    /// Additional gas for `EXP` opcode for each byte of exponent
    pub exp_byte_gas: usize,
    /// Gas price for `SHA3` opcode
    pub sha3_gas: usize,
    /// Additional gas for `SHA3` opcode for each word of hashed memory
    pub sha3_word_gas: usize,
    /// Gas price for loading from storage
    pub sload_gas: usize,
    /// Gas price for setting new value to storage (`storage==0`, `new!=0`)
    pub sstore_set_gas: usize,
    /// Gas price for altering value in storage
    pub sstore_reset_gas: usize,
    /// Gas refund for `SSTORE` clearing (when `storage!=0`, `new==0`)
    pub sstore_refund_gas: usize,
    /// Gas price for `JUMPDEST` opcode
    pub jumpdest_gas: usize,
    /// Gas price for `LOG*`
    pub log_gas: usize,
    /// Additional gas for data in `LOG*`
    pub log_data_gas: usize,
    /// Additional gas for each topic in `LOG*`
    pub log_topic_gas: usize,
    /// Gas price for `CREATE` opcode
    pub create_gas: usize,
    /// Gas price for `*CALL*` opcodes
    pub call_gas: usize,
    /// Stipend for transfer for `CALL|CALLCODE` opcode when `value>0`
    pub call_stipend: usize,
    /// Additional gas required for value transfer (`CALL|CALLCODE`)
    pub call_value_transfer_gas: usize,
    /// Additional gas for creating new account (`CALL|CALLCODE`)
    pub call_new_account_gas: usize,
    /// Refund for SUICIDE
    pub suicide_refund_gas: usize,
    /// Gas for used memory
    pub memory_gas: usize,
    /// Coefficient used to convert memory size to gas price for memory
    pub quad_coeff_div: usize,
    /// Cost for contract length when executing `CREATE`
    pub create_data_gas: usize,
    /// Maximum code size when creating a contract.
    pub create_data_limit: usize,
    /// Transaction cost
    pub tx_gas: usize,
    /// `CREATE` transaction cost
    pub tx_create_gas: usize,
    /// Additional cost for empty data transaction
    pub tx_data_zero_gas: usize,
    /// Aditional cost for non-empty data transaction
    pub tx_data_non_zero_gas: usize,
    /// Gas price for copying memory
    pub copy_gas: usize,
    /// Price of EXTCODESIZE
    pub extcodesize_gas: usize,
    /// Base price of EXTCODECOPY
    pub extcodecopy_base_gas: usize,
    /// Price of BALANCE
    pub balance_gas: usize,
    /// Price of EXTCODEHASH
    pub extcodehash_gas: usize,
    /// Price of SUICIDE
    pub suicide_gas: usize,
    /// Price for retiring PoS node.
    pub retire_gas: usize,
    /// Price for deploying Eip-1820 contract.
    pub eip1820_gas: usize,
    /// Amount of additional gas to pay when SUICIDE credits a non-existant
    /// account
    pub suicide_to_new_account_cost: usize,
    /// If Some(x):
    ///     let limit = GAS * (x - 1) / x;
    ///     let CALL's gas = min(requested, limit);
    ///     let CREATE's gas = limit;
    /// If None:
    ///     let CALL's gas = (requested > GAS ? \[OOG\] : GAS);
    ///     let CREATE's gas = GAS;
    pub sub_gas_cap_divisor: Option<usize>,
    /// Don't ever make empty accounts; contracts start with nonce=1. Also,
    /// don't charge 25k when sending/suicide zero-value.
    pub no_empty: bool,
    /// Kill empty accounts if touched.
    pub kill_empty: bool,
    /// Blockhash instruction gas cost.
    pub blockhash_gas: usize,
    /// Kill basic accounts below this balance if touched.
    pub kill_dust: CleanDustMode,
    /// VM execution does not increase null signed address nonce if this field
    /// is true.
    pub keep_unsigned_nonce: bool,
    /// Wasm extra specs, if wasm activated
    pub wasm: Option<WasmCosts>,
    /// Start nonce for a new contract
    pub contract_start_nonce: U256,
    /// Start nonce for a new account
    pub account_start_nonce: U256,
    /// The magnification of gas storage occupying related operaions.
    pub evm_gas_ratio: usize,
    /// CIP-43: Introduce Finality via Voting Among Staked
    pub cip43_init: bool,
    pub cip43_contract: bool,
    /// CIP-62: Enable EC-related builtin contract
    pub cip62: bool,
    /// CIP-64: Get current epoch number through internal contract
    pub cip64: bool,
    /// CIP-71: Disable anti-reentrancy
    pub cip71: bool,
    /// CIP-78: Correct `is_sponsored` fields in receipt
    pub cip78a: bool,
    /// CIP-78: Correct `is_sponsored` fields in receipt
    pub cip78b: bool,
    /// CIP-90: A Space that Fully EVM Compatible
    pub cip90: bool,
    /// CIP-94: On-chain Parameter DAO Vote
    pub cip94: bool,
    pub cip94_activation_block_number: u64,
    /// CIP-97: Remove staking list
    pub cip97: bool,
    /// CIP-98: Fix espace bug
    pub cip98: bool,
    /// CIP-105: Minimal DAO votes requirement based on PoS votes.
    pub cip105: bool,
    pub params_dao_vote_period: u64,
}

/// Wasm cost table
#[derive(Debug, Clone)]
pub struct WasmCosts {
    /// Default opcode cost
    pub regular: u32,
    /// Div operations multiplier.
    pub div: u32,
    /// Div operations multiplier.
    pub mul: u32,
    /// Memory (load/store) operations multiplier.
    pub mem: u32,
    /// General static query of U256 value from env-info
    pub static_u256: u32,
    /// General static query of Address value from env-info
    pub static_address: u32,
    /// Memory stipend. Amount of free memory (in 64kb pages) each contract
    /// can use for stack.
    pub initial_mem: u32,
    /// Grow memory cost, per page (64kb)
    pub grow_mem: u32,
    /// Memory copy cost, per byte
    pub memcpy: u32,
    /// Max stack height (native WebAssembly stack limiter)
    pub max_stack_height: u32,
    /// Cost of wasm opcode is calculated as TABLE_ENTRY_COST * `opcodes_mul`
    /// / `opcodes_div`
    pub opcodes_mul: u32,
    /// Cost of wasm opcode is calculated as TABLE_ENTRY_COST * `opcodes_mul`
    /// / `opcodes_div`
    pub opcodes_div: u32,
    /// Whether create2 extern function is activated.
    pub have_create2: bool,
    /// Whether gasleft extern function is activated.
    pub have_gasleft: bool,
}

impl Default for WasmCosts {
    fn default() -> Self {
        WasmCosts {
            regular: 1,
            div: 16,
            mul: 4,
            mem: 2,
            static_u256: 64,
            static_address: 40,
            initial_mem: 4096,
            grow_mem: 8192,
            memcpy: 1,
            max_stack_height: 64 * 1024,
            opcodes_mul: 3,
            opcodes_div: 8,
            have_create2: false,
            have_gasleft: false,
        }
    }
}

/// Dust accounts cleanup mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanDustMode {
    /// Dust cleanup is disabled.
    Off,
    /// Basic dust accounts will be removed.
    BasicOnly,
    /// Basic and contract dust accounts will be removed.
    WithCodeAndStorage,
}

impl Spec {
    /// The spec when Conflux launches the mainnet. It should never changed
    /// since the mainnet has launched.
    pub const fn genesis_spec() -> Spec {
        Spec {
            exceptional_failed_code_deposit: true,
            stack_limit: 1024,
            max_depth: 1024,
            tier_step_gas: [0, 2, 3, 5, 8, 10, 20, 0],
            exp_gas: 10,
            exp_byte_gas: 50,
            sha3_gas: 30,
            sha3_word_gas: 6,
            sload_gas: 200,
            sstore_set_gas: 20000,
            sstore_reset_gas: 5000,
            sstore_refund_gas: 15000,
            jumpdest_gas: 1,
            log_gas: 375,
            log_data_gas: 8,
            log_topic_gas: 375,
            create_gas: 32000,
            call_gas: 700,
            call_stipend: 2300,
            call_value_transfer_gas: 9000,
            call_new_account_gas: 25000,
            suicide_refund_gas: 24000,
            memory_gas: 3,
            quad_coeff_div: 512,
            create_data_gas: 200,
            create_data_limit: 49152,
            tx_gas: 21000,
            tx_create_gas: 53000,
            tx_data_zero_gas: 4,
            tx_data_non_zero_gas: 68,
            copy_gas: 3,
            extcodesize_gas: 700,
            extcodecopy_base_gas: 700,
            extcodehash_gas: 400,
            balance_gas: 400,
            suicide_gas: 5000,
            retire_gas: 5_000_000,
            eip1820_gas: 1_500_000,
            suicide_to_new_account_cost: 25000,
            sub_gas_cap_divisor: Some(64),
            no_empty: true,
            kill_empty: true,
            blockhash_gas: 20,
            contract_start_nonce: U256([1, 0, 0, 0]),
            /* If `no_empty` is
             * false, it
             * should be 0. */
            account_start_nonce: U256([0, 0, 0, 0]),
            kill_dust: CleanDustMode::Off,
            keep_unsigned_nonce: false,
            wasm: None,
            cip43_init: false,
            cip43_contract: false,
            cip62: false,
            cip64: false,
            cip71: false,
            cip90: false,
            cip78a: false,
            cip78b: false,
            cip94: false,
            evm_gas_ratio: 2,
            cip94_activation_block_number: u64::MAX,
            params_dao_vote_period: DAO_PARAMETER_VOTE_PERIOD,
            cip97: false,
            cip98: false,
            cip105: false,
        }
    }

    pub fn new_spec_from_common_params(
        params: &CommonParams, number: BlockNumber,
    ) -> Spec {
        let mut spec = Self::genesis_spec();
        spec.cip43_contract = number >= params.transition_numbers.cip43a;
        spec.cip43_init = number >= params.transition_numbers.cip43a
            && number < params.transition_numbers.cip43b;
        spec.cip62 = number >= params.transition_numbers.cip62;
        spec.cip64 = number >= params.transition_numbers.cip64;
        spec.cip71 = number >= params.transition_numbers.cip71;
        spec.cip90 = number >= params.transition_numbers.cip90b;
        spec.cip78a = number >= params.transition_numbers.cip78a;
        spec.cip78b = number >= params.transition_numbers.cip78b;
        spec.cip94 = number >= params.transition_numbers.cip94;
        spec.cip94_activation_block_number = params.transition_numbers.cip94;
        spec.cip97 = number >= params.transition_numbers.cip97;
        spec.cip98 = number >= params.transition_numbers.cip98;
        spec.cip105 = number >= params.transition_numbers.cip105;
        spec.params_dao_vote_period = params.params_dao_vote_period;
        spec
    }

    #[cfg(test)]
    pub fn new_spec_for_test() -> Spec { Self::genesis_spec() }

    /// Returns wasm spec
    ///
    /// May panic if there is no wasm spec
    pub fn wasm(&self) -> &WasmCosts {
        // *** Prefer PANIC here instead of silently breaking consensus! ***
        self.wasm.as_ref().expect("Wasm spec expected to exist while checking wasm contract. Misconfigured client?")
    }

    pub fn is_valid_address(&self, address: &Address) -> bool {
        address.is_genesis_valid_address()
    }
}

#[cfg(test)]
impl Default for Spec {
    fn default() -> Self { Spec::new_spec_for_test() }
}
