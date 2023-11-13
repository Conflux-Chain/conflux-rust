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

//! Return data structures

use cfx_types::U256;

use super::Spec;

/// Return data buffer. Holds memory from a previous call and a slice into that
/// memory.
#[derive(Debug)]
pub struct ReturnData {
    mem: Vec<u8>,
    offset: usize,
    size: usize,
}

impl ::std::ops::Deref for ReturnData {
    type Target = [u8];

    fn deref(&self) -> &[u8] { &self.mem[self.offset..self.offset + self.size] }
}

impl From<Vec<u8>> for ReturnData {
    fn from(value: Vec<u8>) -> Self {
        ReturnData {
            offset: 0,
            size: value.len(),
            mem: value,
        }
    }
}

impl ReturnData {
    /// Create empty `ReturnData`.
    pub fn empty() -> Self {
        ReturnData {
            mem: Vec::new(),
            offset: 0,
            size: 0,
        }
    }

    /// Create `ReturnData` from give buffer and slice.
    pub fn new(mem: Vec<u8>, offset: usize, size: usize) -> Self {
        ReturnData { mem, offset, size }
    }
}

/// Gas Left: either it is a known value, or it needs to be computed by
/// processing a return instruction.
#[derive(Debug)]
pub enum GasLeft {
    /// Known gas left
    Known(U256),
    /// Return or Revert instruction must be processed.
    NeedsReturn {
        /// Amount of gas left.
        gas_left: U256,
        /// Return data buffer.
        data: ReturnData,
        /// Apply or revert state changes on revert.
        apply_state: bool,
    },
}

impl GasLeft {
    pub fn charge_return_data_gas(
        mut self, spec: &Spec,
    ) -> super::Result<GasLeft> {
        match &mut self {
            GasLeft::NeedsReturn { gas_left, data, .. } => {
                let length = data.len();
                let return_cost =
                    U256::from((length + 31) / 32 * spec.memory_gas);

                if *gas_left < return_cost {
                    Err(super::Error::OutOfGas)
                } else {
                    *gas_left -= return_cost;
                    Ok(self)
                }
            }
            _ => Ok(self),
        }
    }
}
