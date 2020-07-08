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

/// Definition of the cost spec and other parameterisations for the VM.
#[derive(Debug, Clone)]
pub struct Spec {
    /// Does it support exceptional failed code deposit
    pub exceptional_failed_code_deposit: bool,
    /// Does it have a delegate cal
    pub have_delegate_call: bool,
    /// Does it have a CREATE2 instruction
    pub have_create2: bool,
    /// Does it have a REVERT instruction
    pub have_revert: bool,
    /// Does it have a EXTCODEHASH instruction
    pub have_extcodehash: bool,
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
    /// Amount of additional gas to pay when SUICIDE credits a non-existant
    /// account
    pub suicide_to_new_account_cost: usize,
    /// If Some(x): let limit = GAS * (x - 1) / x; let CALL's gas =
    /// min(requested, limit). let CREATE's gas = limit. If None: let
    /// CALL's gas =
    /// (requested > GAS
    /// ? [OOG] : GAS).
    /// let CREATE's gas
    /// = GAS
    pub sub_gas_cap_divisor: Option<usize>,
    /// Don't ever make empty accounts; contracts start with nonce=1. Also,
    /// don't charge 25k when sending/suicide zero-value.
    pub no_empty: bool,
    /// Kill empty accounts if touched.
    pub kill_empty: bool,
    /// Blockhash instruction gas cost.
    pub blockhash_gas: usize,
    /// Static Call opcode enabled.
    pub have_static_call: bool,
    /// RETURNDATA and RETURNDATASIZE opcodes enabled.
    pub have_return_data: bool,
    /// BEGINSUB, JUMPSUB, and RETURNSUB opcodes enabled.
    pub have_subs: bool,
    /// CHAINID enabled.
    pub have_chain_id: bool,
    /// SELFBALANCE enabled.
    pub have_self_balance: bool,
    /// SHL, SHR, SAR opcodes enabled.
    pub have_bitwise_shifting: bool,
    /// Kill basic accounts below this balance if touched.
    pub kill_dust: CleanDustMode,
    /// VM execution does not increase null signed address nonce if this field
    /// is true.
    pub keep_unsigned_nonce: bool,
    /// Wasm extra specs, if wasm activated
    pub wasm: Option<WasmCosts>,
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
    pub fn new(
        max_code_size: usize, fix_exp: bool, no_empty: bool, kill_empty: bool,
    ) -> Spec {
        Spec {
            exceptional_failed_code_deposit: true,
            have_delegate_call: true,
            have_create2: false,
            have_revert: false,
            have_return_data: false,
            have_bitwise_shifting: false,
            have_extcodehash: false,
            have_subs: false,
            have_chain_id: false,
            have_self_balance: false,
            stack_limit: 1024,
            max_depth: 1024,
            tier_step_gas: [0, 2, 3, 5, 8, 10, 20, 0],
            exp_gas: 10,
            exp_byte_gas: if fix_exp { 50 } else { 10 },
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
            create_data_limit: max_code_size,
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
            suicide_to_new_account_cost: 25000,
            sub_gas_cap_divisor: Some(64),
            no_empty,
            kill_empty,
            blockhash_gas: 20,
            have_static_call: false,
            kill_dust: CleanDustMode::Off,
            keep_unsigned_nonce: false,
            wasm: None,
        }
    }

    pub fn new_spec() -> Spec {
        let mut spec = Self::new(49152, true, true, true);
        spec.have_create2 = true;
        spec.have_revert = true;
        spec.have_static_call = true;
        spec.have_return_data = true;
        spec.have_bitwise_shifting = true;
        spec.have_extcodehash = true;
        spec.have_subs = true;
        spec.have_chain_id = true;
        spec.have_self_balance = true;
        spec
    }

    /// Returns wasm spec
    ///
    /// May panic if there is no wasm spec
    pub fn wasm(&self) -> &WasmCosts {
        // *** Prefer PANIC here instead of silently breaking consensus! ***
        self.wasm.as_ref().expect("Wasm spec expected to exist while checking wasm contract. Misconfigured client?")
    }
}

impl Default for Spec {
    fn default() -> Self { Spec::new_spec() }
}
