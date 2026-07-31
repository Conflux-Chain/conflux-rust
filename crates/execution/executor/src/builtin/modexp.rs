use super::{Error, Precompile, PricePlan, Pricer};
use byteorder::{BigEndian, ByteOrder};
use cfx_bytes::BytesRef;
use cfx_types::U256;
use cfx_vm_types::Spec;
use num::{BigUint, One, Zero};
use std::{
    cmp::{max, min},
    io::{self, Read},
};

/// EIP-7823: upper bound (in bytes) for each of the base, exponent and
/// modulus length inputs.
const EIP7823_INPUT_LEN_LIMIT: u64 = 1024;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ModexpImpl;

// calculate modexp: left-to-right binary exponentiation to keep multiplicands
// lower
pub fn modexp(mut base: BigUint, exp: Vec<u8>, modulus: BigUint) -> BigUint {
    const BITS_PER_DIGIT: usize = 8;

    // n^m % 0 || n^m % 1
    if modulus <= BigUint::one() {
        return BigUint::zero();
    }

    // normalize exponent
    let mut exp = exp.into_iter().skip_while(|d| *d == 0).peekable();

    // n^0 % m
    if let None = exp.peek() {
        return BigUint::one();
    }

    // 0^n % m, n > 0
    if base.is_zero() {
        return BigUint::zero();
    }

    base = base % &modulus;

    // Fast path for base divisible by modulus.
    if base.is_zero() {
        return BigUint::zero();
    }

    // Left-to-right binary exponentiation (Handbook of Applied Cryptography -
    // Algorithm 14.79). http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf
    let mut result = BigUint::one();

    for digit in exp {
        let mut mask = 1 << (BITS_PER_DIGIT - 1);

        for _ in 0..BITS_PER_DIGIT {
            result = &result * &result % &modulus;

            if digit & mask > 0 {
                result = result * &base % &modulus;
            }

            mask >>= 1;
        }
    }

    result
}

impl Precompile for ModexpImpl {
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        let mut reader = input.chain(io::repeat(0));
        let mut buf = [0; 32];

        // read lengths as usize.
        // ignoring the first 24 bytes might technically lead us to fall out of
        // consensus, but so would running out of addressable memory!
        let mut read_len = |reader: &mut io::Chain<&[u8], io::Repeat>| {
            reader
                .read_exact(&mut buf[..])
                .expect("reading from zero-extended memory cannot fail; qed");
            BigEndian::read_u64(&buf[24..]) as usize
        };

        let base_len = read_len(&mut reader);
        let exp_len = read_len(&mut reader);
        let mod_len = read_len(&mut reader);

        // Gas formula allows arbitrary large exp_len when base and modulus are
        // empty, so we need to handle empty base first.
        let r = if base_len == 0 && mod_len == 0 {
            BigUint::zero()
        } else {
            // read the numbers themselves.
            let mut buf = vec![0; max(mod_len, max(base_len, exp_len))];
            let mut read_num = |reader: &mut io::Chain<&[u8], io::Repeat>,
                                len: usize| {
                reader.read_exact(&mut buf[..len]).expect(
                    "reading from zero-extended memory cannot fail; qed",
                );
                BigUint::from_bytes_be(&buf[..len])
            };

            let base = read_num(&mut reader, base_len);

            let mut exp_buf = vec![0; exp_len];
            reader
                .read_exact(&mut exp_buf[..exp_len])
                .expect("reading from zero-extended memory cannot fail; qed");

            let modulus = read_num(&mut reader, mod_len);

            modexp(base, exp_buf, modulus)
        };

        // write output to given memory, left padded and same length as the
        // modulus.
        let bytes = r.to_bytes_be();

        // always true except in the case of zero-length modulus, which leads to
        // output of length and value 1.
        if bytes.len() <= mod_len {
            let res_start = mod_len - bytes.len();
            output.write(res_start, &bytes);
        }

        Ok(())
    }
}

/// A special pricing model for modular exponentiation.
#[derive(Debug)]
pub(crate) enum ModexpPricer {
    Byzantium { divisor: usize },
    // CIP-645e: EIP-2565
    Berlin { base: usize },
    // CIP-174: EIP-7823 + EIP-7883
    Osaka { base: usize },
}

impl ModexpPricer {
    pub(crate) fn new_byzantium(divisor: usize) -> ModexpPricer {
        ModexpPricer::Byzantium { divisor }
    }

    pub(crate) fn new_berlin(base: usize) -> ModexpPricer {
        ModexpPricer::Berlin { base }
    }

    pub(crate) fn new_osaka(base: usize) -> ModexpPricer {
        ModexpPricer::Osaka { base }
    }
}

/// Selects the modexp pricer by the active spec: Osaka (CIP-174), Berlin
/// (CIP-645e) or Byzantium.
pub(crate) struct ModexpPricePlan {
    osaka: ModexpPricer,
    berlin: ModexpPricer,
    byzantium: ModexpPricer,
}

impl ModexpPricePlan {
    pub(crate) fn new(
        osaka: ModexpPricer, berlin: ModexpPricer, byzantium: ModexpPricer,
    ) -> Self {
        Self {
            osaka,
            berlin,
            byzantium,
        }
    }
}

impl PricePlan for ModexpPricePlan {
    fn pricer(&self, spec: &Spec) -> &dyn Pricer {
        if spec.cip174 {
            &self.osaka
        } else if spec.cip645.eip2565 {
            &self.berlin
        } else {
            &self.byzantium
        }
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

        // EIP-7823: over-limit inputs make the precompile fail; returning
        // the maximal cost makes the call run out of gas, which consumes
        // all gas passed to the call as the EIP requires.
        if matches!(self, Self::Osaka { .. }) {
            let limit = U256::from(EIP7823_INPUT_LEN_LIMIT);
            if base_len > limit || exp_len > limit || mod_len > limit {
                return U256::max_value();
            }
        }

        if mod_len.is_zero() && base_len.is_zero() {
            match self {
                Self::Byzantium { .. } => return 0.into(),
                Self::Berlin { base } => return (*base).into(),
                // EIP-7883: multiplication complexity is at least 16, so a
                // long exponent still charges iteration costs even with
                // empty base and modulus — fall through to the full formula.
                Self::Osaka { .. } => {}
            }
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
        // EIP-7883 doubles the per-byte cost of the exponent tail.
        let exp_byte_factor = match self {
            ModexpPricer::Osaka { .. } => 16,
            _ => 8,
        };
        let iter_count =
            max(Self::adjusted_exp_len(exp_len, exp_low, exp_byte_factor), 1);

        match self {
            ModexpPricer::Byzantium { divisor } => Self::byzantium_gas_calc(
                base_len, mod_len, iter_count, *divisor,
            ),
            ModexpPricer::Berlin { base } => {
                Self::berlin_gas_calc(base_len, mod_len, iter_count, *base)
            }
            ModexpPricer::Osaka { base } => {
                Self::osaka_gas_calc(base_len, mod_len, iter_count, *base)
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

    fn adjusted_exp_len(len: u64, exp_low: U256, byte_factor: u64) -> u64 {
        let bit_index = if exp_low.is_zero() {
            0
        } else {
            (255 - exp_low.leading_zeros()) as u64
        };
        if len <= 32 {
            bit_index
        } else {
            byte_factor * (len - 32) + bit_index
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

    // CIP-174: EIP-7883. Inputs are bounded by EIP-7823 (checked in `cost`),
    // so none of the arithmetic below can overflow u64.
    pub fn osaka_gas_calc(
        base_len: u64, mod_len: u64, iter_count: u64, base_gas: usize,
    ) -> U256 {
        let max_len = max(base_len, mod_len);
        let mut words = max_len / 8;
        if max_len % 8 > 0 {
            words += 1;
        }
        let multiplication_complexity = if max_len <= 32 {
            16
        } else {
            2 * words * words
        };
        let gas = multiplication_complexity * iter_count;
        max(base_gas as u64, gas).into()
    }
}
