use cfx_types::U256;
use std::{
    cmp::{max, min},
    convert::TryInto,
    io::{self, Read},
};

/// A gas pricing scheme for built-in contracts.
pub trait Pricer: Send + Sync {
    /// The gas cost of running this built-in for the given input data.
    fn cost(&self, input: &[u8]) -> U256;
}

/// A linear pricing model. This computes a price using a base cost and a cost
/// per-word.
pub(crate) struct Linear {
    pub(crate) base: usize,
    pub(crate) word: usize,
}

impl Linear {
    pub(crate) fn new(base: usize, word: usize) -> Linear {
        Linear { base, word }
    }
}

pub(crate) struct ConstPricer {
    price: u64,
}

impl ConstPricer {
    pub(crate) const fn new(price: u64) -> ConstPricer { ConstPricer { price } }
}

/// A special pricing model for modular exponentiation.
#[derive(Debug)]
pub(crate) enum ModexpPricer {
    Byzantium { divisor: usize },
    // CIP-645e: EIP-2565
    Berlin { base: usize },
}

impl ModexpPricer {
    pub(crate) fn new_byzantium(divisor: usize) -> ModexpPricer {
        ModexpPricer::Byzantium { divisor }
    }

    pub(crate) fn new_berlin(base: usize) -> ModexpPricer {
        ModexpPricer::Berlin { base }
    }
}

impl Pricer for Linear {
    fn cost(&self, input: &[u8]) -> U256 {
        U256::from(self.base)
            + U256::from(self.word) * U256::from((input.len() + 31) / 32)
    }
}

impl Pricer for ConstPricer {
    fn cost(&self, _input: &[u8]) -> U256 { U256::from(self.price) }
}

/// A alt_bn128_parinig pricing model. This computes a price using a base cost
/// and a cost per pair.
pub(crate) struct AltBn128PairingPricer {
    base: usize,
    pair: usize,
}

impl AltBn128PairingPricer {
    pub(crate) fn new(base: usize, pair: usize) -> AltBn128PairingPricer {
        AltBn128PairingPricer { base, pair }
    }
}

impl Pricer for AltBn128PairingPricer {
    fn cost(&self, input: &[u8]) -> U256 {
        let cost = U256::from(self.base)
            + U256::from(self.pair) * U256::from(input.len() / 192);
        cost
    }
}

impl Pricer for ModexpPricer {
    fn cost(&self, input: &[u8]) -> U256 {
        let mut reader = input.chain(io::repeat(0));
        let mut buf = [0; 32];

        // read lengths as U256 here for accurate gas calculation.
        let mut read_len = || {
            reader
                .read_exact(&mut buf[..])
                .expect("reading from zero-extended memory cannot fail; qed");
            U256::from_big_endian(&buf[..])
        };
        let base_len = read_len();
        let exp_len = read_len();
        let mod_len = read_len();

        if mod_len.is_zero() && base_len.is_zero() {
            return match self {
                Self::Byzantium { .. } => 0.into(),
                Self::Berlin { base } => (*base).into(),
            };
        }

        let max_len = U256::from(u32::max_value() / 2);

        if base_len > max_len || mod_len > max_len || exp_len > max_len {
            return U256::max_value();
        }
        let (base_len, exp_len, mod_len) =
            (base_len.low_u64(), exp_len.low_u64(), mod_len.low_u64());

        // read fist 32-byte word of the exponent.
        let exp_low = if base_len + 96 >= input.len() as u64 {
            U256::zero()
        } else {
            let mut buf = [0; 32];
            let mut reader =
                input[(96 + base_len as usize)..].chain(io::repeat(0));
            let len = min(exp_len, 32) as usize;
            reader
                .read_exact(&mut buf[(32 - len)..])
                .expect("reading from zero-extended memory cannot fail; qed");
            U256::from_big_endian(&buf[..])
        };
        let iter_count = max(Self::adjusted_exp_len(exp_len, exp_low), 1);

        match self {
            ModexpPricer::Byzantium { divisor } => Self::byzantium_gas_calc(
                base_len, mod_len, iter_count, *divisor,
            ),
            ModexpPricer::Berlin { base } => {
                Self::berlin_gas_calc(base_len, mod_len, iter_count, *base)
            }
        }
    }
}

impl ModexpPricer {
    pub fn byzantium_gas_calc(
        base_len: u64, mod_len: u64, iter_count: u64, divisor: usize,
    ) -> U256 {
        let m = max(mod_len, base_len);
        let (gas, overflow) =
            Self::mult_complexity(m).overflowing_mul(iter_count);
        if overflow {
            return U256::max_value();
        }
        (gas / divisor as u64).into()
    }

    fn adjusted_exp_len(len: u64, exp_low: U256) -> u64 {
        let bit_index = if exp_low.is_zero() {
            0
        } else {
            (255 - exp_low.leading_zeros()) as u64
        };
        if len <= 32 {
            bit_index
        } else {
            8 * (len - 32) + bit_index
        }
    }

    fn mult_complexity(x: u64) -> u64 {
        match x {
            x if x <= 64 => x * x,
            x if x <= 1024 => (x * x) / 4 + 96 * x - 3072,
            x => (x * x) / 16 + 480 * x - 199680,
        }
    }

    pub fn berlin_gas_calc(
        base_len: u64, mod_len: u64, iter_count: u64, base_gas: usize,
    ) -> U256 {
        fn calculate_multiplication_complexity(
            base_len: u64, mod_len: u64,
        ) -> U256 {
            let max_len = max(base_len, mod_len);
            let mut words = max_len / 8;
            if max_len % 8 > 0 {
                words += 1;
            }
            let words = U256::from(words);
            words * words
        }

        let multiplication_complexity =
            calculate_multiplication_complexity(base_len, mod_len);
        let gas = (multiplication_complexity * U256::from(iter_count))
            / U256::from(3);
        let gas_u64 = if gas >= U256::from(u64::MAX) {
            u64::MAX
        } else {
            gas.as_u64()
        };
        max(base_gas as u64, gas_u64).into()
    }
}

/// Pricing for Blake2 compression function: each call costs the same amount per
/// round.
pub(crate) struct Blake2FPricer {
    /// Price per round of Blake2 compression function.
    gas_per_round: u64,
}

impl Blake2FPricer {
    pub fn new(gas_per_round: u64) -> Self { Self { gas_per_round } }
}

impl Pricer for Blake2FPricer {
    fn cost(&self, input: &[u8]) -> U256 {
        const FOUR: usize = std::mem::size_of::<u32>();
        // Returning zero if the conversion fails is fine because `execute()`
        // will check the length and bail with the appropriate error.
        if input.len() < FOUR {
            return U256::zero();
        }
        let (rounds_bytes, _) = input.split_at(FOUR);
        let rounds =
            u32::from_be_bytes(rounds_bytes.try_into().unwrap_or([0u8; 4]));
        U256::from(self.gas_per_round * rounds as u64)
    }
}
