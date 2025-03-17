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

use cfx_types::{Address, Space, H256, U256};
use cfx_vm_types::{self as vm, Spec};
use std::{cmp, sync::Arc};
use vm::{BlockHashSource, CODE_PREFIX_7702};

use super::{
    instructions::{self, Instruction, InstructionInfo},
    stack::Stack,
    u256_to_address,
};
use crate::CostType;

macro_rules! overflowing {
    ($x:expr) => {{
        let (v, overflow) = $x;
        if overflow {
            return Err(vm::Error::OutOfGas);
        }
        v
    }};
}

enum Request<Cost: CostType> {
    Gas(Cost),
    GasMem(Cost, Cost),
    GasMemProvide(Cost, Cost, Option<U256>),
    GasMemCopy(Cost, Cost, Cost),
}

pub struct InstructionRequirements<Cost> {
    pub gas_cost: Cost,
    pub provide_gas: Option<Cost>,
    pub memory_total_gas: Cost,
    pub memory_required_size: usize,
    pub gas_refund: i64,
}

pub struct Gasometer<Gas> {
    pub current_gas: Gas,
    pub current_mem_gas: Gas,
}

impl<Gas: CostType> Gasometer<Gas> {
    pub fn new(current_gas: Gas) -> Self {
        Gasometer {
            current_gas,
            current_mem_gas: Gas::from(0),
        }
    }

    pub fn verify_gas(&self, gas_cost: &Gas) -> vm::Result<()> {
        match &self.current_gas < gas_cost {
            true => Err(vm::Error::OutOfGas),
            false => Ok(()),
        }
    }

    /// How much gas is provided to a CALL/CREATE, given that we need to deduct
    /// `needed` for this operation and that we `requested` some.
    pub fn gas_provided(
        &self, spec: &Spec, needed: Gas, requested: Option<U256>,
    ) -> vm::Result<Gas> {
        // Try converting requested gas to `Gas` (`U256/u64`)
        let requested = requested.map(Gas::from_u256);

        match spec.sub_gas_cap_divisor {
            Some(cap_divisor) if self.current_gas >= needed => {
                let gas_remaining = self.current_gas - needed;
                let max_gas_provided = match cap_divisor {
                    64 => gas_remaining - (gas_remaining >> 6),
                    cap_divisor => {
                        gas_remaining - gas_remaining / Gas::from(cap_divisor)
                    }
                };

                if let Some(Ok(r)) = requested {
                    Ok(cmp::min(r, max_gas_provided))
                } else {
                    Ok(max_gas_provided)
                }
            }
            _ => {
                if let Some(r) = requested {
                    r
                } else if self.current_gas >= needed {
                    Ok(self.current_gas - needed)
                } else {
                    Ok(0.into())
                }
            }
        }
    }

    /// Determine how much gas is used by the given instruction, given the
    /// machine's state.
    ///
    /// We guarantee that the final element of the returned tuple (`provided`)
    /// will be `Some` iff the `instruction` is one of `CREATE`, or any of
    /// the `CALL` variants. In this case, it will be the amount of gas
    /// that the current context
    /// provides to the child context.
    pub fn requirements(
        &mut self, context: &dyn vm::Context, instruction: Instruction,
        info: &InstructionInfo, stack: &dyn Stack<U256>,
        current_mem_size: usize,
    ) -> vm::Result<InstructionRequirements<Gas>> {
        let spec = context.spec();
        let tier = info.tier.idx();
        let default_gas = Gas::from(spec.tier_step_gas[tier]);

        let account_access_gas = |idx: usize| {
            let address = u256_to_address(stack.peek(idx));
            if context.is_warm_account(address) {
                spec.warm_access_gas
            } else {
                spec.cold_account_access_cost
            }
        };

        let mut gas_refund = 0;

        let cost = match instruction {
            instructions::JUMPDEST => Request::Gas(Gas::from(1)),
            instructions::SSTORE => {
                let (to_charge_gas, to_refund_gas) =
                    calc_sstore_gas(context, stack, self.current_gas)?;
                gas_refund += to_refund_gas;
                Request::Gas(Gas::from(to_charge_gas))
            }
            instructions::SLOAD => {
                let gas = if spec.cip645 {
                    let mut key = H256::zero();
                    stack.peek(0).to_big_endian(&mut key.0);
                    if context.is_warm_storage_entry(&key)? {
                        spec.warm_access_gas
                    } else {
                        spec.cold_sload_gas
                    }
                } else {
                    spec.sload_gas()
                };
                Request::Gas(Gas::from(gas))
            }
            instructions::BALANCE => {
                let gas = if spec.cip645 {
                    account_access_gas(0)
                } else {
                    spec.balance_gas
                };
                Request::Gas(Gas::from(gas))
            }
            instructions::EXTCODESIZE => {
                let gas = if spec.cip645 {
                    account_access_gas(0)
                } else {
                    spec.extcodesize_gas
                };
                Request::Gas(Gas::from(gas))
            }
            instructions::EXTCODEHASH => {
                let gas = if spec.cip645 {
                    account_access_gas(0)
                } else {
                    spec.extcodehash_gas
                };
                Request::Gas(Gas::from(gas))
            }
            instructions::SUICIDE => {
                let mut gas = Gas::from(spec.suicide_gas);

                let is_value_transfer = !context.origin_balance()?.is_zero();
                let address = u256_to_address(stack.peek(0));
                if spec.cip645 && !context.is_warm_account(address) {
                    gas += Gas::from(spec.cold_account_access_cost);
                }
                if (!spec.no_empty && !context.exists(&address)?)
                    || (spec.no_empty
                        && is_value_transfer
                        && !context.exists_and_not_null(&address)?)
                {
                    let ratio = if context.space() == Space::Ethereum {
                        spec.evm_gas_ratio
                    } else {
                        1
                    };
                    gas = overflowing!(gas.overflow_add(
                        (spec.suicide_to_new_account_cost * ratio).into()
                    ));
                }

                Request::Gas(gas)
            }
            instructions::MSTORE | instructions::MLOAD => Request::GasMem(
                default_gas,
                mem_needed_const(stack.peek(0), 32)?,
            ),
            instructions::MSTORE8 => Request::GasMem(
                default_gas,
                mem_needed_const(stack.peek(0), 1)?,
            ),
            instructions::RETURN | instructions::REVERT => Request::GasMem(
                default_gas,
                mem_needed(stack.peek(0), stack.peek(1))?,
            ),
            instructions::SHA3 => {
                let words =
                    overflowing!(to_word_size(Gas::from_u256(*stack.peek(1))?));
                let gas = overflowing!(Gas::from(spec.sha3_gas).overflow_add(
                    overflowing!(
                        Gas::from(spec.sha3_word_gas).overflow_mul(words)
                    )
                ));
                Request::GasMem(gas, mem_needed(stack.peek(0), stack.peek(1))?)
            }
            instructions::CALLDATACOPY
            | instructions::CODECOPY
            | instructions::RETURNDATACOPY => Request::GasMemCopy(
                default_gas,
                mem_needed(stack.peek(0), stack.peek(2))?,
                Gas::from_u256(*stack.peek(2))?,
            ),
            instructions::JUMPSUB_MCOPY if spec.cancun_opcodes => {
                Request::GasMemCopy(
                    default_gas,
                    mem_needed(stack.peek(0), stack.peek(2))?,
                    Gas::from_u256(*stack.peek(2))?,
                )
            }
            instructions::BEGINSUB_TLOAD if spec.cancun_opcodes => {
                Request::Gas(Gas::from(spec.warm_access_gas))
            }
            instructions::RETURNSUB_TSTORE if spec.cancun_opcodes => {
                Request::Gas(Gas::from(spec.warm_access_gas))
            }
            instructions::EXTCODECOPY => {
                let base_gas = if spec.cip645 {
                    account_access_gas(0)
                } else {
                    spec.extcodecopy_base_gas
                };
                Request::GasMemCopy(
                    base_gas.into(),
                    mem_needed(stack.peek(1), stack.peek(3))?,
                    Gas::from_u256(*stack.peek(3))?,
                )
            }
            instructions::LOG0
            | instructions::LOG1
            | instructions::LOG2
            | instructions::LOG3
            | instructions::LOG4 => {
                let no_of_topics = instruction.log_topics().expect(
                    "log_topics always return some for LOG* instructions; qed",
                );
                let log_gas = spec.log_gas + spec.log_topic_gas * no_of_topics;

                let data_gas = overflowing!(Gas::from_u256(*stack.peek(1))?
                    .overflow_mul(Gas::from(spec.log_data_gas)));
                let gas =
                    overflowing!(data_gas.overflow_add(Gas::from(log_gas)));
                Request::GasMem(gas, mem_needed(stack.peek(0), stack.peek(1))?)
            }
            instructions::CALL | instructions::CALLCODE => {
                let mut gas =
                    Gas::from(calc_call_gas(context, stack, self.current_gas)?);
                let mem = cmp::max(
                    mem_needed(stack.peek(5), stack.peek(6))?,
                    mem_needed(stack.peek(3), stack.peek(4))?,
                );

                let address = u256_to_address(stack.peek(1));
                let is_value_transfer = !stack.peek(2).is_zero();

                if instruction == instructions::CALL
                    && ((!spec.no_empty && !context.exists(&address)?)
                        || (spec.no_empty
                            && is_value_transfer
                            && !context.exists_and_not_null(&address)?))
                {
                    let ratio = if context.space() == Space::Ethereum {
                        spec.evm_gas_ratio
                    } else {
                        1
                    };
                    gas = overflowing!(gas.overflow_add(
                        (spec.call_new_account_gas * ratio).into()
                    ));
                }

                if is_value_transfer {
                    gas =
                        overflowing!(gas
                            .overflow_add(spec.call_value_transfer_gas.into()));
                }

                let requested = *stack.peek(0);

                Request::GasMemProvide(gas, mem, Some(requested))
            }
            instructions::DELEGATECALL | instructions::STATICCALL => {
                let gas =
                    Gas::from(calc_call_gas(context, stack, self.current_gas)?);
                let mem = cmp::max(
                    mem_needed(stack.peek(4), stack.peek(5))?,
                    mem_needed(stack.peek(2), stack.peek(3))?,
                );
                let requested = *stack.peek(0);

                Request::GasMemProvide(gas, mem, Some(requested))
            }
            instructions::CREATE | instructions::CREATE2 => {
                let start = stack.peek(1);
                let len = stack.peek(2);
                let base = Gas::from(spec.create_gas);
                let word = overflowing!(to_word_size(Gas::from_u256(*len)?));

                let sha3_word_price = if instruction == instructions::CREATE
                    && context.space() == Space::Ethereum
                {
                    // CREATE operation in espace doesn't compute code_hash
                    0
                } else {
                    spec.sha3_word_gas
                };
                let init_code_word_price = if spec.cip645 {
                    // CIP-645i: EIP-3860
                    spec.init_code_word_gas
                } else {
                    0
                };
                let word_price = sha3_word_price + init_code_word_price;
                let word_gas =
                    overflowing!(Gas::from(word_price).overflow_mul(word));

                let gas = overflowing!(base.overflow_add(word_gas));
                let mem = mem_needed(start, len)?;

                Request::GasMemProvide(gas, mem, None)
            }
            instructions::EXP => {
                let expon = stack.peek(1);
                let bytes = ((expon.bits() + 7) / 8) as usize;
                let gas = Gas::from(spec.exp_gas + spec.exp_byte_gas * bytes);
                Request::Gas(gas)
            }
            instructions::BLOCKHASH => {
                let block_number = stack.peek(0);
                let gas = if context.space() == Space::Ethereum
                    && spec.align_evm
                {
                    spec.blockhash_gas
                } else if !spec.cip645 {
                    match context.blockhash_source() {
                        BlockHashSource::Env => spec.blockhash_gas,
                        BlockHashSource::State => spec.sload_gas(),
                    }
                } else if block_number > &U256::from(u64::MAX) {
                    spec.warm_access_gas
                } else {
                    let block_number = block_number.as_u64();
                    let env = context.env();

                    let diff = match context.space() {
                        Space::Native => env.number.checked_sub(block_number),
                        Space::Ethereum => {
                            env.epoch_height.checked_sub(block_number)
                        }
                    };
                    if diff.map_or(false, |x| x > 256 && x < 65536) {
                        spec.cold_sload_gas
                    } else {
                        spec.warm_access_gas
                    }
                };

                Request::Gas(Gas::from(gas))
            }
            _ => Request::Gas(default_gas),
        };

        Ok(match cost {
            Request::Gas(gas) => InstructionRequirements {
                gas_cost: gas,
                provide_gas: None,
                memory_required_size: 0,
                memory_total_gas: self.current_mem_gas,
                gas_refund,
            },
            Request::GasMem(gas, mem_size) => {
                let (mem_gas_cost, new_mem_gas, new_mem_size) =
                    self.mem_gas_cost(spec, current_mem_size, &mem_size)?;
                let gas = overflowing!(gas.overflow_add(mem_gas_cost));
                InstructionRequirements {
                    gas_cost: gas,
                    provide_gas: None,
                    memory_required_size: new_mem_size,
                    memory_total_gas: new_mem_gas,
                    gas_refund,
                }
            }
            Request::GasMemProvide(gas, mem_size, requested) => {
                let (mem_gas_cost, new_mem_gas, new_mem_size) =
                    self.mem_gas_cost(spec, current_mem_size, &mem_size)?;
                let gas = overflowing!(gas.overflow_add(mem_gas_cost));
                let provided = self.gas_provided(spec, gas, requested)?;
                let total_gas = overflowing!(gas.overflow_add(provided));

                InstructionRequirements {
                    gas_cost: total_gas,
                    provide_gas: Some(provided),
                    memory_required_size: new_mem_size,
                    memory_total_gas: new_mem_gas,
                    gas_refund,
                }
            }
            Request::GasMemCopy(gas, mem_size, copy) => {
                let (mem_gas_cost, new_mem_gas, new_mem_size) =
                    self.mem_gas_cost(spec, current_mem_size, &mem_size)?;
                let copy = overflowing!(to_word_size(copy));
                let copy_gas =
                    overflowing!(Gas::from(spec.copy_gas).overflow_mul(copy));
                let gas = overflowing!(gas.overflow_add(copy_gas));
                let gas = overflowing!(gas.overflow_add(mem_gas_cost));

                InstructionRequirements {
                    gas_cost: gas,
                    provide_gas: None,
                    memory_required_size: new_mem_size,
                    memory_total_gas: new_mem_gas,
                    gas_refund,
                }
            }
        })
    }

    fn mem_gas_cost(
        &self, spec: &Spec, current_mem_size: usize, mem_size: &Gas,
    ) -> vm::Result<(Gas, Gas, usize)> {
        let gas_for_mem = |mem_size: Gas| {
            let s = mem_size >> 5;
            // s * memory_gas + s * s / quad_coeff_div
            let a = overflowing!(s.overflow_mul(Gas::from(spec.memory_gas)));

            // Calculate s*s/quad_coeff_div
            assert_eq!(spec.quad_coeff_div, 512);
            let b = overflowing!(s.overflow_mul_shr(s, 9));
            Ok(overflowing!(a.overflow_add(b)))
        };

        let current_mem_size = Gas::from(current_mem_size);
        let req_mem_size_rounded = overflowing!(to_word_size(*mem_size)) << 5;

        let (mem_gas_cost, new_mem_gas) =
            if req_mem_size_rounded > current_mem_size {
                let new_mem_gas = gas_for_mem(req_mem_size_rounded)?;
                (new_mem_gas - self.current_mem_gas, new_mem_gas)
            } else {
                (Gas::from(0), self.current_mem_gas)
            };

        Ok((mem_gas_cost, new_mem_gas, req_mem_size_rounded.as_usize()))
    }
}

#[inline]
fn mem_needed_const<Gas: CostType>(mem: &U256, add: usize) -> vm::Result<Gas> {
    Gas::from_u256(overflowing!(mem.overflowing_add(U256::from(add))))
}

#[inline]
fn mem_needed<Gas: CostType>(offset: &U256, size: &U256) -> vm::Result<Gas> {
    if size.is_zero() {
        return Ok(Gas::from(0));
    }

    Gas::from_u256(overflowing!(offset.overflowing_add(*size)))
}

#[inline]
fn add_gas_usize<Gas: CostType>(value: Gas, num: usize) -> (Gas, bool) {
    value.overflow_add(Gas::from(num))
}

#[inline]
fn to_word_size<Gas: CostType>(value: Gas) -> (Gas, bool) {
    let (gas, overflow) = add_gas_usize(value, 31);
    if overflow {
        return (gas, overflow);
    }

    (gas >> 5, false)
}

fn calc_sstore_gas<Gas: CostType>(
    context: &dyn vm::Context, stack: &dyn Stack<U256>, current_gas: Gas,
) -> vm::Result<(usize, i64)> {
    let spec = context.spec();
    let space = context.space();

    if space == Space::Native && !spec.cip645 {
        // The only simple case without checking values
        return Ok((spec.sstore_reset_gas, 0));
    }

    if current_gas <= spec.call_stipend.into() {
        // Enough to trigger the OutOfGas, no need for further checks
        return Ok((spec.call_stipend + 1, 0));
    }

    let mut key = H256::zero();
    stack.peek(0).to_big_endian(&mut key.0);

    let new_val = *stack.peek(1);
    let warm_val = context.is_warm_storage_entry(&key)?;
    let cur_val = context.storage_at(&key[..])?;

    if !spec.cip645 {
        // For eSpace only, the core space before cip645 has been filtted out.
        return Ok(if cur_val.is_zero() && !new_val.is_zero() {
            (spec.sstore_set_gas * spec.evm_gas_ratio, 0)
        } else {
            (spec.sstore_reset_gas, 0)
        });
    }

    let ori_val = context.origin_storage_at(&key[..])?.unwrap();

    let is_noop = new_val == cur_val;
    let is_clean = ori_val == cur_val;

    // CIP-645(d, f): EIP-2200 + EIP-2929
    let charge_gas = if is_noop {
        // no storage op, just load cost for checking
        spec.warm_access_gas
    } else if is_clean && ori_val.is_zero() && space == Space::Ethereum {
        // charge storage write gas + storage occupation gas
        spec.sstore_set_gas * spec.evm_gas_ratio
    } else if is_clean {
        spec.sstore_reset_gas
    } else {
        // other operations has paid for storage write cost
        spec.warm_access_gas
    };

    // CIP-645f: EIP-2929
    let cold_warm_gas = if warm_val { 0 } else { spec.cold_sload_gas };

    let sstore_clear_refund_gas = if space == Space::Ethereum && !is_noop {
        // CIP-645g (EIP-3529) updates the value defined in CIP-645d (EIP-2200)
        let sstore_clears_schedule =
            (spec.sstore_reset_gas + spec.access_list_storage_key_gas) as i64;
        match (ori_val.is_zero(), cur_val.is_zero(), new_val.is_zero()) {
            (false, false, true) => {
                // First time release this entry
                sstore_clears_schedule
            }
            (false, true, false) => {
                // Used to release but occupy again, undo refund
                -sstore_clears_schedule
            }
            _ => 0,
        }
    } else {
        0
    };

    let not_write_db_refund_gas = if ori_val == new_val {
        if ori_val.is_zero() && space == Space::Ethereum {
            // charge storage write gas + storage occupation gas
            spec.sstore_set_gas * spec.evm_gas_ratio
        } else {
            spec.sstore_reset_gas
        }
    } else {
        0
    };

    Ok((
        charge_gas + cold_warm_gas,
        sstore_clear_refund_gas + not_write_db_refund_gas as i64,
    ))
}

fn calc_call_gas<Gas: CostType>(
    context: &dyn vm::Context, stack: &dyn Stack<U256>, current_gas: Gas,
) -> vm::Result<usize> {
    let spec = context.spec();
    if !spec.cip645 {
        return Ok(spec.call_gas);
    }

    let address = u256_to_address(stack.peek(1));
    let call_gas = if context.is_warm_account(address) {
        spec.warm_access_gas
    } else {
        spec.cold_account_access_cost
    };

    if current_gas < call_gas.into() {
        // Enough to trigger the out-of-gas
        return Ok(call_gas);
    }

    let Some(delegated_address) = delegated_address(context.extcode(&address)?)
    else {
        return Ok(call_gas);
    };

    Ok(call_gas
        + if context.is_warm_account(delegated_address) {
            spec.warm_access_gas
        } else {
            spec.cold_account_access_cost
        })
}

fn delegated_address(extcode: Option<Arc<Vec<u8>>>) -> Option<Address> {
    let code = extcode?;
    if !code.starts_with(CODE_PREFIX_7702) {
        return None;
    }

    let (_prefix, payload) = code.split_at(CODE_PREFIX_7702.len());

    if payload.len() == Address::len_bytes() {
        Some(Address::from_slice(payload))
    } else {
        None
    }
}

#[test]
fn test_mem_gas_cost() {
    // given
    let gasometer = Gasometer::<U256>::new(U256::zero());
    let spec = Spec::default();
    let current_mem_size = 5;
    let mem_size = !U256::zero();

    // when
    let result = gasometer.mem_gas_cost(&spec, current_mem_size, &mem_size);

    // then
    if result.is_ok() {
        assert!(false, "Should fail with OutOfGas");
    }
}

#[test]
fn test_calculate_mem_cost() {
    // given
    let gasometer = Gasometer::<usize>::new(0);
    let spec = Spec::default();
    let current_mem_size = 0;
    let mem_size = 5;

    // when
    let (mem_cost, new_mem_gas, mem_size) = gasometer
        .mem_gas_cost(&spec, current_mem_size, &mem_size)
        .unwrap();

    // then
    assert_eq!(mem_cost, 3);
    assert_eq!(new_mem_gas, 3);
    assert_eq!(mem_size, 32);
}
