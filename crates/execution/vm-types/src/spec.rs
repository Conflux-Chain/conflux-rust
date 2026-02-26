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
use cfx_types::{address_util::AddressUtil, Address};
use primitives::{block::BlockHeight, BlockNumber};

pub const CODE_PREFIX_7702: &'static [u8] = b"\xef\x01\x00";

/// Definition of the cost spec and other parameterisations for the VM.
#[derive(Debug, Clone)]
pub struct Spec {
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
    /// Gas price for loading from storage. Code sload gas after CIP-645f:
    /// EIP-2929
    pub cold_sload_gas: usize,
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
    /// Maximum init code size (CIP-645i: EIP-3860)
    pub init_code_data_limit: usize,
    /// Init code word size (CIP-645i: EIP-3860)
    pub init_code_word_gas: usize,
    /// Transaction cost
    pub tx_gas: usize,
    /// `CREATE` transaction cost
    pub tx_create_gas: usize,
    /// Additional cost for empty data transaction
    pub tx_data_zero_gas: usize,
    /// Aditional cost for non-empty data transaction
    pub tx_data_non_zero_gas: usize,
    /// Floor gas cost from empty data transaction (EIP-7623)
    pub tx_data_floor_zero_gas: usize,
    /// Floor gas cost from non-empty data transaction (EIP-7623)
    pub tx_data_floor_non_zero_gas: usize,
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
    pub access_list_storage_key_gas: usize,
    pub access_list_address_gas: usize,
    pub cold_account_access_cost: usize,
    pub warm_access_gas: usize,
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
    /// Blockhash instruction gas cost.
    pub blockhash_gas: usize,
    /// The magnification of gas storage occupying related operaions.
    pub evm_gas_ratio: usize,
    /// `PER_AUTH_BASE_COST` in CIP-7702
    pub per_auth_base_cost: usize,
    /// `PER_EMPTY_ACCOUNT_COST` in CIP-7702
    pub per_empty_account_cost: usize,
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
    pub params_dao_vote_period: u64,
    /// CIP-97: Remove staking list
    pub cip97: bool,
    /// CIP-98: Fix espace bug
    pub cip98: bool,
    /// CIP-105: Minimal DAO votes requirement based on PoS votes.
    pub cip105: bool,
    pub cip_sigma_fix: bool,
    /// CIP-107: Reduce storage collateral refund.
    pub cip107: bool,
    /// CIP-118: Query Unused Storage Points in Internal Contract
    pub cip118: bool,
    /// CIP-119: PUSH0 instruction
    pub cip119: bool,
    /// CIP-131: Retain Whitelist on Contract Deletion
    pub cip131: bool,
    /// CIP-132: Fix Static Context Check for Internal Contracts
    pub cip132: bool,
    /// CIP-133: Enhanced Block Hash Query
    pub cip133_b: BlockNumber,
    pub cip133_e: BlockHeight,
    pub cip133_core: bool,
    /// CIP-137: Base Fee Sharing in CIP-1559
    pub cip137: bool,
    /// CIP-1559: Fee Market Change for Conflux
    pub cip1559: bool,
    /// CIP-141: Disable Subroutine Opcodes
    /// CIP-142: Transient Storage Opcodes
    /// CIP-143: MCOPY (0x5e) Opcode for Efficient Memory Copy
    pub cancun_opcodes: bool,
    /// CIP-144: Point Evaluation Precompile from EIP-4844
    pub cip144: bool,
    /// CIP-145: Fix Receipts upon `NotEnoughBalance` Error
    pub cip145: bool,
    pub cip145_fix: bool,
    /// CIP-150: Reject New Contract Code Starting with the 0xEF byte
    pub cip150: bool,
    /// CIP-151: SELFDESTRUCT only in Same Transaction
    pub cip151: bool,
    /// CIP-152: Reject Transactions from Senders with Deployed Code
    pub cip152: bool,
    /// CIP-154: Fix Inconsistent Implementation of TLOAD
    pub cip154: bool,
    /// CIP-7702: Set Code for EOA
    pub cip7702: bool,
    /// CIP-645: Align Conflux Gas Pricing with EVM
    pub cip645: CIP645Spec,
    /// EIP-2935: Serve historical block hashes from state
    pub eip2935: bool,
    /// EIP-7623: Increase calldata cost
    pub eip7623: bool,
    pub align_evm: bool,
    pub cip_c2_fix: bool,
    /// EIP-7939: Count Leading Zeros Instruction
    pub eip7939: bool,
}

/// Represents the feature flags for CIP-645 implementation.
///
/// While the protocol treats these features as a single atomic upgrade,
/// separating them into named fields is merely to make the code more
/// maintainable and self-documenting.
///
/// IMPORTANT NOTE:
/// All fields must be consistently set to either `true` (enabled) or `false`
/// (disabled). Mixed states will lead to undefined behavior as these features
/// were designed to be activated as a coordinated bundle in CIP-645.
#[derive(Debug, Clone, Copy)]
pub struct CIP645Spec {
    /// EIP-1108: Reduces gas costs for alt_bn128 precompile  
    pub eip1108: bool,

    /// EIP-1884: Reprices trie-size-dependent opcodes  
    pub eip1884: bool,

    /// EIP-2028: Reduces Calldata gas cost  
    pub eip2028: bool,

    /// EIP-2200: Rebalances net-metered SSTORE gas cost  
    /// EIP-3529: Removes gas refunds for SELFDESTRUCT and reduces SSTORE
    /// refunds
    pub eip_sstore_and_refund_gas: bool,

    /// EIP-2565: Reduces gas cost for modular exponentiation transactions  
    pub eip2565: bool,

    /// EIP-2929: Increases gas costs for opcode transactions to mitigate DDoS
    /// EIP-3651: Reduces gas fees for accessing COINBASE address  
    pub eip_cold_warm_access: bool,

    /// EIP-3860: Limits initcode size to 49152  
    pub eip3860: bool,

    /// EIP-684: Revert creation in case of collision
    pub fix_eip684: bool,

    /// EIP-1559: EIP-1559: Fee market change for ETH 1.0 chain
    pub fix_eip1559: bool,

    /// EIP-5656: MCOPY - Memory copying instruction
    pub fix_eip5656: bool,

    /// EIP-1153: Transient storage opcodes
    pub fix_eip1153: bool,

    pub blockhash_gas: bool,

    pub opcode_update: bool,

    pub fix_extcodehash: bool,
}

impl CIP645Spec {
    pub const fn new(enabled: bool) -> Self {
        Self {
            eip1108: enabled,
            eip1884: enabled,
            eip2028: enabled,
            eip_sstore_and_refund_gas: enabled,
            eip2565: enabled,
            eip_cold_warm_access: enabled,
            eip3860: enabled,
            fix_eip684: enabled,
            fix_eip1153: enabled,
            fix_eip1559: enabled,
            fix_eip5656: enabled,
            blockhash_gas: enabled,
            opcode_update: enabled,
            fix_extcodehash: enabled,
        }
    }
}

/// Spec parameters are determined solely by block height and thus accessible to
/// the consensus protocol.
#[derive(Debug, Clone)]
pub struct ConsensusGasSpec {
    /// EIP-7623: Increase calldata cost
    pub eip7623: bool,
    /// CIP-1559: Fee Market Change for Conflux
    pub cip1559: bool,
    /// CIP-645(GAS)
    pub cip645: CIP645Spec,
    /// Transaction cost
    pub tx_gas: usize,
    /// `CREATE` transaction cost
    pub tx_create_gas: usize,
    /// Additional cost for empty data transaction
    pub tx_data_zero_gas: usize,
    /// Aditional cost for non-empty data transaction
    pub tx_data_non_zero_gas: usize,
    /// Floor gas cost from empty data transaction (EIP-7623)
    pub tx_data_floor_zero_gas: usize,
    /// Floor gas cost from non-empty data transaction (EIP-7623)
    pub tx_data_floor_non_zero_gas: usize,
    /// Maximum init code size (CIP-645i: EIP-3860)
    pub init_code_data_limit: usize,
    /// Init code word size (CIP-645i: EIP-3860)
    pub init_code_word_gas: usize,
    pub access_list_storage_key_gas: usize,
    pub access_list_address_gas: usize,
    /// `PER_AUTH_BASE_COST` in CIP-7702
    pub per_auth_base_cost: usize,
    /// `PER_EMPTY_ACCOUNT_COST` in CIP-7702
    pub per_empty_account_cost: usize,
    /// The magnification of gas storage occupying related operaions.
    pub evm_gas_ratio: usize,
    pub align_evm: bool,
}

impl Spec {
    /// The spec when Conflux launches the mainnet. It should never changed
    /// since the mainnet has launched.
    pub const fn genesis_spec() -> Spec {
        Spec {
            stack_limit: 1024,
            max_depth: 1024,
            tier_step_gas: [0, 2, 3, 5, 8, 10, 20, 0],
            exp_gas: 10,
            exp_byte_gas: 50,
            sha3_gas: 30,
            sha3_word_gas: 6,
            // Become 800 after CIP-142
            cold_sload_gas: 200,
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
            init_code_data_limit: 49152,
            init_code_word_gas: 2,
            tx_gas: 21000,
            tx_create_gas: 53000,
            tx_data_zero_gas: 4,
            tx_data_non_zero_gas: 68,
            tx_data_floor_zero_gas: 10,
            tx_data_floor_non_zero_gas: 40,
            copy_gas: 3,
            extcodesize_gas: 700,
            extcodecopy_base_gas: 700,
            extcodehash_gas: 400,
            balance_gas: 400,
            suicide_gas: 5000,
            retire_gas: 5_000_000,
            eip1820_gas: 1_500_000,
            access_list_storage_key_gas: 1900,
            access_list_address_gas: 2400,
            cold_account_access_cost: 2600,
            warm_access_gas: 100,
            suicide_to_new_account_cost: 25000,
            per_auth_base_cost: 17000,
            per_empty_account_cost: 25000,
            sub_gas_cap_divisor: Some(64),
            blockhash_gas: 20,
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
            params_dao_vote_period: 0,
            cip97: false,
            cip98: false,
            cip105: false,
            cip_sigma_fix: false,
            cip107: false,
            cip118: false,
            cip119: false,
            cip131: false,
            cip132: false,
            cip133_b: u64::MAX,
            cip133_e: u64::MAX,
            cip133_core: false,
            cip137: false,
            cip145: false,
            cip145_fix: false,
            cip1559: false,
            cancun_opcodes: false,
            cip144: false,
            cip150: false,
            cip151: false,
            cip152: false,
            cip154: false,
            cip645: CIP645Spec::new(false),
            cip7702: false,
            eip2935: false,
            eip7623: false,
            cip_c2_fix: false,
            align_evm: false,
            eip7939: false,
        }
    }

    // `cold_sload_gas` replaces `sload_gas` in certain contexts, primarily for
    // core space internal contracts. However, some `sload_gas` usages retain
    // their original semantics. This function is introduced to distinguish
    // these cases.
    pub fn sload_gas(&self) -> usize {
        assert!(!self.cip645.eip_cold_warm_access);
        self.cold_sload_gas
    }

    pub fn overwrite_gas_plan_by_cip(&mut self) {
        if self.cancun_opcodes {
            self.cold_sload_gas = 800;
        }
        if self.cip645.eip1884 {
            self.balance_gas = 700;
            self.extcodehash_gas = 700;
        }

        if self.cip645.eip2028 {
            self.tx_data_non_zero_gas = 16;
        }

        if self.cip645.eip_cold_warm_access {
            self.cold_sload_gas = 2100;
            self.sstore_reset_gas = 2900;
        }

        if self.align_evm {
            self.per_auth_base_cost = 12500;
            self.create_data_limit = 24576;
            self.evm_gas_ratio = 1;
        }

        // Don't forget also update GenesisGasSpec::overwrite_gas_plan_by_cip
    }

    #[cfg(any(test, feature = "testonly_code"))]
    pub fn new_spec_for_test() -> Spec { Self::genesis_spec() }

    pub fn is_valid_address(&self, address: &Address) -> bool {
        address.is_genesis_valid_address()
    }

    #[inline]
    pub const fn to_consensus_spec(&self) -> ConsensusGasSpec {
        ConsensusGasSpec {
            cip1559: self.cip1559,
            cip645: self.cip645,
            eip7623: self.eip7623,
            tx_gas: self.tx_gas,
            tx_create_gas: self.tx_create_gas,
            tx_data_zero_gas: self.tx_data_zero_gas,
            tx_data_non_zero_gas: self.tx_data_non_zero_gas,
            init_code_data_limit: self.init_code_data_limit,
            init_code_word_gas: self.init_code_word_gas,
            access_list_storage_key_gas: self.access_list_storage_key_gas,
            access_list_address_gas: self.access_list_address_gas,
            per_auth_base_cost: self.per_auth_base_cost,
            per_empty_account_cost: self.per_empty_account_cost,
            align_evm: self.align_evm,
            evm_gas_ratio: self.evm_gas_ratio,
            tx_data_floor_zero_gas: self.tx_data_floor_zero_gas,
            tx_data_floor_non_zero_gas: self.tx_data_floor_non_zero_gas,
        }
    }
}

impl ConsensusGasSpec {
    pub const fn genesis_spec() -> Self {
        Spec::genesis_spec().to_consensus_spec()
    }

    pub fn overwrite_gas_plan_by_cip(&mut self) {
        if self.cip645.eip2028 {
            self.tx_data_non_zero_gas = 16;
        }

        if self.align_evm {
            self.per_auth_base_cost = 12500;
            self.evm_gas_ratio = 1;
        }
    }
}

#[cfg(any(test, feature = "testonly_code"))]
impl Default for Spec {
    fn default() -> Self { Spec::new_spec_for_test() }
}

pub fn extract_7702_payload(code: &[u8]) -> Option<Address> {
    if code.starts_with(CODE_PREFIX_7702) {
        let (_prefix, payload) = code.split_at(CODE_PREFIX_7702.len());
        if payload.len() == Address::len_bytes() {
            Some(Address::from_slice(payload))
        } else {
            None
        }
    } else {
        None
    }
}
