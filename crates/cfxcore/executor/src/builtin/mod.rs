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

//! Standard built-in contracts.

mod blake2f;
mod ethereum_trusted_setup_points;
mod executable;
mod kzg_point_evaluations;

pub use executable::BuiltinExec;

use std::{
    cmp::{max, min},
    convert::TryInto,
    io::{self, Cursor, Read},
    mem::size_of,
};

use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use cfx_bytes::BytesRef;
use cfx_types::{Space, H256, U256};
use cfxkey::{public_to_address, recover as ec_recover, Address, Signature};
use num::{BigUint, One, Zero};
use parity_crypto::digest;

use blake2f::compress;

/// Execution error.
#[derive(Debug)]
pub struct Error(pub &'static str);

impl From<&'static str> for Error {
    fn from(val: &'static str) -> Self { Error(val) }
}

impl Into<cfx_vm_types::Error> for Error {
    fn into(self) -> cfx_vm_types::Error {
        cfx_vm_types::Error::BuiltIn(self.0)
    }
}

/// Native implementation of a built-in contract.
pub trait Impl: Send + Sync {
    /// execute this built-in on the given input, writing to the given output.
    fn execute(&self, input: &[u8], output: &mut BytesRef)
        -> Result<(), Error>;
}

/// A gas pricing scheme for built-in contracts.
pub trait Pricer: Send + Sync {
    /// The gas cost of running this built-in for the given input data.
    fn cost(&self, input: &[u8]) -> U256;
}

/// A linear pricing model. This computes a price using a base cost and a cost
/// per-word.
#[allow(dead_code)]
pub(crate) struct Linear {
    base: usize,
    word: usize,
}

impl Linear {
    pub(crate) fn new(base: usize, word: usize) -> Linear {
        Linear { base, word }
    }
}

/// A special pricing model for modular exponentiation.
pub(crate) struct ModexpPricer {
    divisor: usize,
}

impl ModexpPricer {
    pub(crate) fn new(divisor: usize) -> ModexpPricer {
        ModexpPricer { divisor }
    }
}

impl Pricer for Linear {
    fn cost(&self, input: &[u8]) -> U256 {
        U256::from(self.base)
            + U256::from(self.word) * U256::from((input.len() + 31) / 32)
    }
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
            return U256::zero();
        }

        let max_len = U256::from(u32::max_value() / 2);
        if base_len > max_len || mod_len > max_len || exp_len > max_len {
            return U256::max_value();
        }
        let (base_len, exp_len, mod_len) =
            (base_len.low_u64(), exp_len.low_u64(), mod_len.low_u64());

        let m = max(mod_len, base_len);
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

        let adjusted_exp_len = Self::adjusted_exp_len(exp_len, exp_low);

        let (gas, overflow) =
            Self::mult_complexity(m).overflowing_mul(max(adjusted_exp_len, 1));
        if overflow {
            return U256::max_value();
        }
        (gas / self.divisor as u64).into()
    }
}

impl ModexpPricer {
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

/// Pricing scheme, execution definition, and activation block for a built-in
/// contract.
///
/// Call `cost` to compute cost for the given input, `execute` to execute the
/// contract on the given input, and `is_active` to determine whether the
/// contract is active.
///
/// Unless `is_active` is true,
pub struct Builtin {
    pricer: Box<dyn Pricer>,
    native: Box<dyn Impl>,
    activate_at: u64,
}

impl Builtin {
    /// Simple forwarder for cost.
    pub fn cost(&self, input: &[u8]) -> U256 { self.pricer.cost(input) }

    /// Simple forwarder for execute.
    pub fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        self.native.execute(input, output)
    }

    /// Whether the builtin is activated at the given cardinal number.
    pub fn is_active(&self, at: u64) -> bool { at >= self.activate_at }

    pub fn new(
        pricer: Box<dyn Pricer>, native: Box<dyn Impl>, activate_at: u64,
    ) -> Builtin {
        Builtin {
            pricer,
            native,
            activate_at,
        }
    }
}

/// Built-in instruction factory.
pub fn builtin_factory(name: &str) -> Box<dyn Impl> {
    match name {
        "identity" => Box::new(Identity) as Box<dyn Impl>,
        "ecrecover" => Box::new(EcRecover(Space::Native)) as Box<dyn Impl>,
        "ecrecover_evm" => {
            Box::new(EcRecover(Space::Ethereum)) as Box<dyn Impl>
        }
        "sha256" => Box::new(Sha256) as Box<dyn Impl>,
        "ripemd160" => Box::new(Ripemd160) as Box<dyn Impl>,
        "modexp" => Box::new(ModexpImpl) as Box<dyn Impl>,
        "alt_bn128_add" => Box::new(Bn128AddImpl) as Box<dyn Impl>,
        "alt_bn128_mul" => Box::new(Bn128MulImpl) as Box<dyn Impl>,
        "alt_bn128_pairing" => Box::new(Bn128PairingImpl) as Box<dyn Impl>,
        "blake2_f" => Box::new(Blake2FImpl) as Box<dyn Impl>,
        "kzg_point_eval" => Box::new(KzgPointEval) as Box<dyn Impl>,
        _ => panic!("invalid builtin name: {}", name),
    }
}

// Builtins:
//
// - The identity function
// - ec recovery
// - sha256
// - ripemd160
// - modexp (EIP198)

#[derive(Debug)]
#[allow(dead_code)]
struct Identity;

#[derive(Debug)]
#[allow(dead_code)]
struct EcRecover(Space);

#[derive(Debug)]
#[allow(dead_code)]
struct Sha256;

#[derive(Debug)]
#[allow(dead_code)]
struct Ripemd160;

#[derive(Debug)]
#[allow(dead_code)]
struct ModexpImpl;

#[derive(Debug)]
#[allow(dead_code)]
struct Bn128AddImpl;

#[derive(Debug)]
#[allow(dead_code)]
struct Bn128MulImpl;

#[derive(Debug)]
#[allow(dead_code)]
struct Bn128PairingImpl;

#[derive(Debug)]
#[allow(dead_code)]
struct Blake2FImpl;

#[derive(Debug)]
#[allow(dead_code)]
struct KzgPointEval;

impl Impl for Identity {
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        output.write(0, input);
        Ok(())
    }
}

impl Impl for EcRecover {
    fn execute(&self, i: &[u8], output: &mut BytesRef) -> Result<(), Error> {
        let len = min(i.len(), 128);

        let mut input = [0; 128];
        input[..len].copy_from_slice(&i[..len]);

        let hash = H256::from_slice(&input[0..32]);
        let v = H256::from_slice(&input[32..64]);
        let r = H256::from_slice(&input[64..96]);
        let s = H256::from_slice(&input[96..128]);

        let bit = match v[31] {
            0 | 1 if &v.0[..31] == &[0; 31] => v[31],
            27 | 28 if &v.0[..31] == &[0; 31] => v[31] - 27,
            _ => {
                return Ok(());
            }
        };

        let s = Signature::from_rsv(&r, &s, bit);
        if s.is_valid() {
            if let Ok(p) = ec_recover(&s, &hash) {
                // We use public_to_address() here
                let addr = public_to_address(&p, self.0 == Space::Native);
                output.write(0, &[0; 12]);
                output.write(12, &addr[0..Address::len_bytes()]);
            }
        }

        Ok(())
    }
}

impl Impl for Sha256 {
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        let d = digest::sha256(input);
        output.write(0, &*d);
        Ok(())
    }
}

impl Impl for Ripemd160 {
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        let hash = digest::ripemd160(input);
        output.write(0, &[0; 12][..]);
        output.write(12, &hash);
        Ok(())
    }
}

// calculate modexp: left-to-right binary exponentiation to keep multiplicands
// lower
fn modexp(mut base: BigUint, exp: Vec<u8>, modulus: BigUint) -> BigUint {
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

impl Impl for ModexpImpl {
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

fn read_fr(
    reader: &mut io::Chain<&[u8], io::Repeat>,
) -> Result<crate::bn::Fr, Error> {
    let mut buf = [0u8; 32];

    reader
        .read_exact(&mut buf[..])
        .expect("reading from zero-extended memory cannot fail; qed");
    crate::bn::Fr::from_slice(&buf[0..32])
        .map_err(|_| Error::from("Invalid field element"))
}

fn read_point(
    reader: &mut io::Chain<&[u8], io::Repeat>,
) -> Result<crate::bn::G1, Error> {
    use crate::bn::{AffineG1, Fq, Group, G1};

    let mut buf = [0u8; 32];

    reader
        .read_exact(&mut buf[..])
        .expect("reading from zero-extended memory cannot fail; qed");
    let px = Fq::from_slice(&buf[0..32])
        .map_err(|_| Error::from("Invalid point x coordinate"))?;

    reader
        .read_exact(&mut buf[..])
        .expect("reading from zero-extended memory cannot fail; qed");
    let py = Fq::from_slice(&buf[0..32])
        .map_err(|_| Error::from("Invalid point y coordinate"))?;
    Ok(if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py)
            .map_err(|_| Error::from("Invalid curve point"))?
            .into()
    })
}

impl Impl for Bn128AddImpl {
    // Can fail if any of the 2 points does not belong the bn128 curve
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        use crate::bn::AffineG1;

        let mut padded_input = input.chain(io::repeat(0));
        let p1 = read_point(&mut padded_input)?;
        let p2 = read_point(&mut padded_input)?;

        let mut write_buf = [0u8; 64];
        if let Some(sum) = AffineG1::from_jacobian(p1 + p2) {
            // point not at infinity
            sum.x()
                .to_big_endian(&mut write_buf[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            sum.y()
                .to_big_endian(&mut write_buf[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }
        output.write(0, &write_buf);

        Ok(())
    }
}

impl Impl for Bn128MulImpl {
    // Can fail if first paramter (bn128 curve point) does not actually belong
    // to the curve
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        use crate::bn::AffineG1;

        let mut padded_input = input.chain(io::repeat(0));
        let p = read_point(&mut padded_input)?;
        let fr = read_fr(&mut padded_input)?;

        let mut write_buf = [0u8; 64];
        if let Some(sum) = AffineG1::from_jacobian(p * fr) {
            // point not at infinity
            sum.x()
                .to_big_endian(&mut write_buf[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            sum.y()
                .to_big_endian(&mut write_buf[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }
        output.write(0, &write_buf);
        Ok(())
    }
}

impl Impl for Bn128PairingImpl {
    /// Can fail if:
    ///     - input length is not a multiple of 192
    ///     - any of odd points does not belong to bn128 curve
    ///     - any of even points does not belong to the twisted bn128 curve
    /// over the field F_p^2 = F_p[i] / (i^2 + 1)
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        if input.len() % 192 != 0 {
            return Err(
                "Invalid input length, must be multiple of 192 (3 * (32*2))"
                    .into(),
            );
        }

        if let Err(err) = self.execute_with_error(input, output) {
            trace!("Pairining error: {:?}", err);
            return Err(err);
        }
        Ok(())
    }
}

impl Bn128PairingImpl {
    fn execute_with_error(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        use crate::bn::{
            pairing, AffineG1, AffineG2, Fq, Fq2, Group, Gt, G1, G2,
        };

        let elements = input.len() / 192; // (a, b_a, b_b - each 64-byte affine coordinates)
        let ret_val = if input.len() == 0 {
            U256::one()
        } else {
            let mut vals = Vec::new();
            for idx in 0..elements {
                let a_x = Fq::from_slice(&input[idx * 192..idx * 192 + 32])
                    .map_err(|_| {
                        Error::from("Invalid a argument x coordinate")
                    })?;

                let a_y =
                    Fq::from_slice(&input[idx * 192 + 32..idx * 192 + 64])
                        .map_err(|_| {
                            Error::from("Invalid a argument y coordinate")
                        })?;

                let b_a_y =
                    Fq::from_slice(&input[idx * 192 + 64..idx * 192 + 96])
                        .map_err(|_| {
                            Error::from(
                        "Invalid b argument imaginary coeff x coordinate",
                    )
                        })?;

                let b_a_x =
                    Fq::from_slice(&input[idx * 192 + 96..idx * 192 + 128])
                        .map_err(|_| {
                            Error::from(
                        "Invalid b argument imaginary coeff y coordinate",
                    )
                        })?;

                let b_b_y =
                    Fq::from_slice(&input[idx * 192 + 128..idx * 192 + 160])
                        .map_err(|_| {
                            Error::from(
                                "Invalid b argument real coeff x coordinate",
                            )
                        })?;

                let b_b_x =
                    Fq::from_slice(&input[idx * 192 + 160..idx * 192 + 192])
                        .map_err(|_| {
                            Error::from(
                                "Invalid b argument real coeff y coordinate",
                            )
                        })?;

                let b_a = Fq2::new(b_a_x, b_a_y);
                let b_b = Fq2::new(b_b_x, b_b_y);
                let b = if b_a.is_zero() && b_b.is_zero() {
                    G2::zero()
                } else {
                    G2::from(AffineG2::new(b_a, b_b).map_err(|_| {
                        Error::from("Invalid b argument - not on curve")
                    })?)
                };
                let a = if a_x.is_zero() && a_y.is_zero() {
                    G1::zero()
                } else {
                    G1::from(AffineG1::new(a_x, a_y).map_err(|_| {
                        Error::from("Invalid a argument - not on curve")
                    })?)
                };
                vals.push((a, b));
            }

            let mul = vals
                .into_iter()
                .fold(Gt::one(), |s, (a, b)| s * pairing(a, b));

            if mul == Gt::one() {
                U256::one()
            } else {
                U256::zero()
            }
        };

        let mut buf = [0u8; 32];
        ret_val.to_big_endian(&mut buf);
        output.write(0, &buf);

        Ok(())
    }
}

impl Impl for Blake2FImpl {
    /// Format of `input`:
    /// [4 bytes for rounds][64 bytes for h][128 bytes for m][8 bytes for t_0][8
    /// bytes for t_1][1 byte for f]
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        const BLAKE2_F_ARG_LEN: usize = 213;
        const PROOF: &str = "Checked the length of the input above; qed";

        if input.len() != BLAKE2_F_ARG_LEN {
            trace!(target: "builtin", "input length for Blake2 F precompile should be exactly 213 bytes, was {}", input.len());
            return Err("input length for Blake2 F precompile should be exactly 213 bytes".into());
        }

        let mut cursor = Cursor::new(input);
        let rounds = cursor.read_u32::<BigEndian>().expect(PROOF);

        // state vector, h
        let mut h = [0u64; 8];
        for state_word in &mut h {
            *state_word = cursor.read_u64::<LittleEndian>().expect(PROOF);
        }

        // message block vector, m
        let mut m = [0u64; 16];
        for msg_word in &mut m {
            *msg_word = cursor.read_u64::<LittleEndian>().expect(PROOF);
        }

        // 2w-bit offset counter, t
        let t = [
            cursor.read_u64::<LittleEndian>().expect(PROOF),
            cursor.read_u64::<LittleEndian>().expect(PROOF),
        ];

        // final block indicator flag, "f"
        let f = match input.last() {
            Some(1) => true,
            Some(0) => false,
            _ => {
                trace!(target: "builtin", "incorrect final block indicator flag, was: {:?}", input.last());
                return Err("incorrect final block indicator flag".into());
            }
        };

        compress(&mut h, m, t, f, rounds as usize);

        let mut output_buf = [0u8; 8 * size_of::<u64>()];
        for (i, state_word) in h.iter().enumerate() {
            output_buf[i * 8..(i + 1) * 8]
                .copy_from_slice(&state_word.to_le_bytes());
        }
        output.write(0, &output_buf[..]);
        Ok(())
    }
}

impl Impl for KzgPointEval {
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        kzg_point_evaluations::run(input)?;
        output.write(0, &kzg_point_evaluations::RETURN_VALUE[..]);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::{
        builtin_factory, modexp as me, Blake2FPricer, Builtin, Linear,
        ModexpPricer, Pricer,
    };
    use cfx_bytes::BytesRef;
    use cfx_types::U256;
    use num::{BigUint, One, Zero};
    use rustc_hex::FromHex;

    #[test]
    fn modexp_func() {
        // n^0 % m == 1
        let mut base = BigUint::parse_bytes(b"12345", 10).unwrap();
        let mut exp = BigUint::zero();
        let mut modulus = BigUint::parse_bytes(b"789", 10).unwrap();
        assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::one());

        // 0^n % m == 0
        base = BigUint::zero();
        exp = BigUint::parse_bytes(b"12345", 10).unwrap();
        modulus = BigUint::parse_bytes(b"789", 10).unwrap();
        assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::zero());

        // n^m % 1 == 0
        base = BigUint::parse_bytes(b"12345", 10).unwrap();
        exp = BigUint::parse_bytes(b"789", 10).unwrap();
        modulus = BigUint::one();
        assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::zero());

        // if n % d == 0, then n^m % d == 0
        base = BigUint::parse_bytes(b"12345", 10).unwrap();
        exp = BigUint::parse_bytes(b"789", 10).unwrap();
        modulus = BigUint::parse_bytes(b"15", 10).unwrap();
        assert_eq!(me(base, exp.to_bytes_be(), modulus), BigUint::zero());

        // others
        base = BigUint::parse_bytes(b"12345", 10).unwrap();
        exp = BigUint::parse_bytes(b"789", 10).unwrap();
        modulus = BigUint::parse_bytes(b"97", 10).unwrap();
        assert_eq!(
            me(base, exp.to_bytes_be(), modulus),
            BigUint::parse_bytes(b"55", 10).unwrap()
        );
    }

    #[test]
    fn identity() {
        let f = builtin_factory("identity");

        let i = [0u8, 1, 2, 3];

        let mut o2 = [255u8; 2];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o2[..]))
            .expect("Builtin should not fail");
        assert_eq!(i[0..2], o2);

        let mut o4 = [255u8; 4];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o4[..]))
            .expect("Builtin should not fail");
        assert_eq!(i, o4);

        let mut o8 = [255u8; 8];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..]))
            .expect("Builtin should not fail");
        assert_eq!(i, o8[..4]);
        assert_eq!([255u8; 4], o8[4..]);
    }

    #[test]
    fn sha256() {
        let f = builtin_factory("sha256");

        let i = [0u8; 0];

        let mut o = [255u8; 32];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".from_hex::<Vec<u8>>().unwrap())[..]);

        let mut o8 = [255u8; 8];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..]))
            .expect("Builtin should not fail");
        assert_eq!(
            &o8[..],
            &("e3b0c44298fc1c14".from_hex::<Vec<u8>>().unwrap())[..]
        );

        let mut o34 = [255u8; 34];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o34[..], &("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855ffff".from_hex::<Vec<u8>>().unwrap())[..]);

        let mut ov = vec![];
        f.execute(&i[..], &mut BytesRef::Flexible(&mut ov))
            .expect("Builtin should not fail");
        assert_eq!(&ov[..], &("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".from_hex::<Vec<u8>>().unwrap())[..]);
    }

    #[test]
    fn ripemd160() {
        let f = builtin_factory("ripemd160");

        let i = [0u8; 0];

        let mut o = [255u8; 32];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31".from_hex::<Vec<u8>>().unwrap())[..]);

        let mut o8 = [255u8; 8];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..]))
            .expect("Builtin should not fail");
        assert_eq!(
            &o8[..],
            &("0000000000000000".from_hex::<Vec<u8>>().unwrap())[..]
        );

        let mut o34 = [255u8; 34];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o34[..], &("0000000000000000000000009c1185a5c5e9fc54612808977ee8f548b2258d31ffff".from_hex::<Vec<u8>>().unwrap())[..]);
    }

    #[test]
    fn ecrecover() {
        let f = builtin_factory("ecrecover");

        let i: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();

        let mut o = [255u8; 32];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("000000000000000000000000108b5542d177ac6686946920409741463a15dddb".from_hex::<Vec<u8>>().unwrap())[..]);

        let i2: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad0000000000000000000000000000000000000000000000000000000000000000650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();

        let mut o2 = [255u8; 32];
        f.execute(&i2[..], &mut BytesRef::Fixed(&mut o2[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o2[..], &("000000000000000000000000108b5542d177ac6686946920409741463a15dddb".from_hex::<Vec<u8>>().unwrap())[..]);

        let mut o8 = [255u8; 8];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o8[..]))
            .expect("Builtin should not fail");
        assert_eq!(
            &o8[..],
            &("0000000000000000".from_hex::<Vec<u8>>().unwrap())[..]
        );

        let mut o34 = [255u8; 34];
        f.execute(&i[..], &mut BytesRef::Fixed(&mut o34[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o34[..], &("000000000000000000000000108b5542d177ac6686946920409741463a15dddbffff".from_hex::<Vec<u8>>().unwrap())[..]);

        let i_bad: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001a650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();
        let mut o = [255u8; 32];
        f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".from_hex::<Vec<u8>>().unwrap())[..]);

        let i_bad: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b000000000000000000000000000000000000000000000000000000000000001b0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let mut o = [255u8; 32];
        f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".from_hex::<Vec<u8>>().unwrap())[..]);

        let i_bad: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b").unwrap();
        let mut o = [255u8; 32];
        f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".from_hex::<Vec<u8>>().unwrap())[..]);

        let i_bad: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000001b").unwrap();
        let mut o = [255u8; 32];
        f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".from_hex::<Vec<u8>>().unwrap())[..]);

        let i_bad: Vec<u8> = FromHex::from_hex("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b000000000000000000000000000000000000000000000000000000000000001bffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let mut o = [255u8; 32];
        f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(&o[..], &("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".from_hex::<Vec<u8>>().unwrap())[..]);

        // TODO: Should this (corrupted version of the above) fail rather than
        // returning some address?
        /*	let i_bad = FromHex::from_hex("48173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad000000000000000000000000000000000000000000000000000000000000001b650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e03").unwrap();
        let mut o = [255u8; 32];
        f.execute(&i_bad[..], &mut BytesRef::Fixed(&mut o[..]));
        assert_eq!(&o[..], &("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".from_hex::<Vec<u8>>().unwrap())[..]);*/
    }

    #[test]
    fn modexp() {
        let f = Builtin {
            pricer: Box::new(ModexpPricer { divisor: 20 }),
            native: builtin_factory("modexp"),
            activate_at: 0,
        };

        // test for potential gas cost multiplication overflow
        {
            let input: Vec<u8> = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000003b27bafd00000000000000000000000000000000000000000000000000000000503c8ac3").unwrap();
            let expected_cost = U256::max_value();
            assert_eq!(f.cost(&input[..]), expected_cost.into());
        }

        // test for potential exp len overflow
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				00000000000000000000000000000000000000000000000000000000000000ff\
				2a1e530000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let mut output = vec![0u8; 32];
            let expected: Vec<u8> = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
            let expected_cost = U256::max_value();

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should fail");
            assert_eq!(output, expected);
            assert_eq!(f.cost(&input[..]), expected_cost.into());
        }

        // fermat's little theorem example.
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000001\
				0000000000000000000000000000000000000000000000000000000000000020\
				0000000000000000000000000000000000000000000000000000000000000020\
				03\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            )
            .unwrap();

            let mut output = vec![0u8; 32];
            let expected: Vec<u8> = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
            let expected_cost = 13056;

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should not fail");
            assert_eq!(output, expected);
            assert_eq!(f.cost(&input[..]), expected_cost.into());
        }

        // zero base.
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000020\
				0000000000000000000000000000000000000000000000000000000000000020\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e\
				fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            )
            .unwrap();

            let mut output = vec![0u8; 32];
            let expected: Vec<u8> = FromHex::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
            let expected_cost = 13056;

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should not fail");
            assert_eq!(output, expected);
            assert_eq!(f.cost(&input[..]), expected_cost.into());
        }

        // zero-padding
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000001\
				0000000000000000000000000000000000000000000000000000000000000002\
				0000000000000000000000000000000000000000000000000000000000000020\
				03\
				ffff\
				80",
            )
            .unwrap();

            let mut output = vec![0u8; 32];
            let expected: Vec<u8> = FromHex::from_hex("3b01b01ac41f2d6e917c6d6a221ce793802469026d9ab7578fa2e79e4da6aaab").unwrap();
            let expected_cost = 768;

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should not fail");
            assert_eq!(output, expected);
            assert_eq!(f.cost(&input[..]), expected_cost.into());
        }

        // zero-length modulus.
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000001\
				0000000000000000000000000000000000000000000000000000000000000002\
				0000000000000000000000000000000000000000000000000000000000000000\
				03\
				ffff",
            )
            .unwrap();

            let mut output = vec![];
            let expected_cost = 0;

            f.execute(&input[..], &mut BytesRef::Flexible(&mut output))
                .expect("Builtin should not fail");
            assert_eq!(output.len(), 0); // shouldn't have written any output.
            assert_eq!(f.cost(&input[..]), expected_cost.into());
        }
    }

    #[test]
    fn bn128_add() {
        let f = Builtin {
            pricer: Box::new(Linear { base: 0, word: 0 }),
            native: builtin_factory("alt_bn128_add"),
            activate_at: 0,
        };

        // zero-points additions
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let mut output = vec![0u8; 64];
            let expected: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should not fail");
            assert_eq!(output, expected);
        }

        // no input, should not fail
        {
            let mut empty = [0u8; 0];
            let input = BytesRef::Fixed(&mut empty);

            let mut output = vec![0u8; 64];
            let expected: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should not fail");
            assert_eq!(output, expected);
        }

        // should fail - point not on curve
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap();

            let mut output = vec![0u8; 64];

            let res =
                f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]));
            assert!(res.is_err(), "There should be built-in error here");
        }
    }

    #[test]
    fn bn128_mul() {
        let f = Builtin {
            pricer: Box::new(Linear { base: 0, word: 0 }),
            native: builtin_factory("alt_bn128_mul"),
            activate_at: 0,
        };

        // zero-point multiplication
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000\
				0200000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let mut output = vec![0u8; 64];
            let expected: Vec<u8> = FromHex::from_hex(
                "\
				0000000000000000000000000000000000000000000000000000000000000000\
				0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
                .expect("Builtin should not fail");
            assert_eq!(output, expected);
        }

        // should fail - point not on curve
        {
            let input: Vec<u8> = FromHex::from_hex(
                "\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				0f00000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap();

            let mut output = vec![0u8; 64];

            let res =
                f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]));
            assert!(res.is_err(), "There should be built-in error here");
        }
    }

    fn builtin_pairing() -> Builtin {
        Builtin {
            pricer: Box::new(Linear { base: 0, word: 0 }),
            native: builtin_factory("alt_bn128_pairing"),
            activate_at: 0,
        }
    }

    fn empty_test(f: Builtin, expected: Vec<u8>) {
        let mut empty = [0u8; 0];
        let input = BytesRef::Fixed(&mut empty);

        let mut output = vec![0u8; expected.len()];

        f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
            .expect("Builtin should not fail");
        assert_eq!(output, expected);
    }

    fn error_test(f: Builtin, input: &[u8], msg_contains: Option<&str>) {
        let mut output = vec![0u8; 64];
        let res = f.execute(input, &mut BytesRef::Fixed(&mut output[..]));
        if let Some(msg) = msg_contains {
            if let Err(e) = res {
                if !e.0.contains(msg) {
                    panic!("There should be error containing '{}' here, but got: '{}'", msg, e.0);
                }
            }
        } else {
            assert!(res.is_err(), "There should be built-in error here");
        }
    }

    fn bytes(s: &'static str) -> Vec<u8> {
        FromHex::from_hex(s).expect("static str should contain valid hex bytes")
    }

    #[test]
    fn bn128_pairing_empty() {
        // should not fail, because empty input is a valid input of 0 elements
        empty_test(
            builtin_pairing(),
            bytes("0000000000000000000000000000000000000000000000000000000000000001"),
        );
    }

    #[test]
    fn bn128_pairing_notcurve() {
        // should fail - point not on curve
        error_test(
            builtin_pairing(),
            &bytes(
                "\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111",
            ),
            Some("not on curve"),
        );
    }

    #[test]
    fn bn128_pairing_fragmented() {
        // should fail - input length is invalid
        error_test(
            builtin_pairing(),
            &bytes(
                "\
				1111111111111111111111111111111111111111111111111111111111111111\
				1111111111111111111111111111111111111111111111111111111111111111\
				111111111111111111111111111111",
            ),
            Some("Invalid input length"),
        );
    }

    #[test]
    #[should_panic]
    fn from_unknown_linear() { let _ = builtin_factory("foo"); }

    #[test]
    fn is_active() {
        let pricer = Box::new(Linear { base: 10, word: 20 });
        let b = Builtin {
            pricer: pricer as Box<dyn Pricer>,
            native: builtin_factory("identity"),
            activate_at: 100_000,
        };

        assert!(!b.is_active(99_999));
        assert!(b.is_active(100_000));
        assert!(b.is_active(100_001));
    }

    #[test]
    fn from_named_linear() {
        let pricer = Box::new(Linear { base: 10, word: 20 });
        let b = Builtin {
            pricer: pricer as Box<dyn Pricer>,
            native: builtin_factory("identity"),
            activate_at: 1,
        };

        assert_eq!(b.cost(&[0; 0]), U256::from(10));
        assert_eq!(b.cost(&[0; 1]), U256::from(30));
        assert_eq!(b.cost(&[0; 32]), U256::from(30));
        assert_eq!(b.cost(&[0; 33]), U256::from(50));

        let i = [0u8, 1, 2, 3];
        let mut o = [255u8; 4];
        b.execute(&i[..], &mut BytesRef::Fixed(&mut o[..]))
            .expect("Builtin should not fail");
        assert_eq!(i, o);
    }

    fn blake2f_builtin() -> Builtin {
        Builtin {
            pricer: Box::new(Blake2FPricer::new(123)) as Box<dyn Pricer>,
            native: builtin_factory("blake2_f"),
            activate_at: 0,
        }
    }

    #[test]
    fn blake2f_cost() {
        let f = blake2f_builtin();
        // 5 rounds
        let input : Vec<u8> = FromHex::from_hex("0000000548c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let mut output = [0u8; 64];
        f.execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
            .unwrap();

        assert_eq!(f.cost(&input[..]), U256::from(123 * 5));
    }

    #[test]
    fn blake2f_cost_on_invalid_length() {
        let f = blake2f_builtin();
        // invalid input (too short)
        let input: Vec<u8> = FromHex::from_hex("00").unwrap();

        assert_eq!(f.cost(&input[..]), U256::from(0));
    }

    #[test]
    fn blake2_f_is_err_on_invalid_length() {
        let blake2 = blake2f_builtin();
        // Test vector 1 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-1
        let input : Vec<u8> = FromHex::from_hex("00000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let mut out = [0u8; 64];

        let result =
            blake2.execute(&input[..], &mut BytesRef::Fixed(&mut out[..]));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().0,
            "input length for Blake2 F precompile should be exactly 213 bytes"
        );
    }

    #[test]
    fn blake2_f_is_err_on_invalid_length_2() {
        let blake2 = blake2f_builtin();
        // Test vector 2 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-2
        let input : Vec<u8> = FromHex::from_hex("000000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let mut out = [0u8; 64];

        let result =
            blake2.execute(&input[..], &mut BytesRef::Fixed(&mut out[..]));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().0,
            "input length for Blake2 F precompile should be exactly 213 bytes"
        );
    }

    #[test]
    fn blake2_f_is_err_on_bad_finalization_flag() {
        let blake2 = blake2f_builtin();
        // Test vector 3 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-3
        let input : Vec<u8> = FromHex::from_hex("0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000002").unwrap();
        let mut out = [0u8; 64];

        let result =
            blake2.execute(&input[..], &mut BytesRef::Fixed(&mut out[..]));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().0,
            "incorrect final block indicator flag"
        );
    }

    #[test]
    fn blake2_f_zero_rounds_is_ok_test_vector_4() {
        let blake2 = blake2f_builtin();
        // Test vector 4 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-4
        let input : Vec<u8> = FromHex::from_hex("0000000048c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let expected : Vec<u8> = FromHex::from_hex("08c9bcf367e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d282e6ad7f520e511f6c3e2b8c68059b9442be0454267ce079217e1319cde05b").unwrap();
        let mut output = [0u8; 64];
        blake2
            .execute(&input[..], &mut BytesRef::Fixed(&mut output[..]))
            .unwrap();
        assert_eq!(&output[..], &expected[..]);
    }

    #[test]
    fn blake2_f_test_vector_5() {
        let blake2 = blake2f_builtin();
        // Test vector 5 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-5
        let input : Vec<u8> = FromHex::from_hex("0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let expected : Vec<u8> = FromHex::from_hex("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923").unwrap();
        let mut out = [0u8; 64];
        blake2
            .execute(&input[..], &mut BytesRef::Fixed(&mut out[..]))
            .unwrap();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn blake2_f_test_vector_6() {
        let blake2 = blake2f_builtin();
        // Test vector 6 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-6
        let input : Vec<u8> = FromHex::from_hex("0000000c48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000").unwrap();
        let expected : Vec<u8> = FromHex::from_hex("75ab69d3190a562c51aef8d88f1c2775876944407270c42c9844252c26d2875298743e7f6d5ea2f2d3e8d226039cd31b4e426ac4f2d3d666a610c2116fde4735").unwrap();
        let mut out = [0u8; 64];
        blake2
            .execute(&input[..], &mut BytesRef::Fixed(&mut out[..]))
            .unwrap();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn blake2_f_test_vector_7() {
        let blake2 = blake2f_builtin();
        // Test vector 7 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-7
        let input : Vec<u8> = FromHex::from_hex("0000000148c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let expected : Vec<u8> = FromHex::from_hex("b63a380cb2897d521994a85234ee2c181b5f844d2c624c002677e9703449d2fba551b3a8333bcdf5f2f7e08993d53923de3d64fcc68c034e717b9293fed7a421").unwrap();
        let mut out = [0u8; 64];
        blake2
            .execute(&input[..], &mut BytesRef::Fixed(&mut out[..]))
            .unwrap();
        assert_eq!(&out[..], &expected[..]);
    }

    #[ignore]
    #[test]
    fn blake2_f_test_vector_8() {
        let blake2 = blake2f_builtin();
        // Test vector 8 and expected output from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-152.md#test-vector-8
        // Note this test is slow, 4294967295/0xffffffff rounds take a while.
        let input : Vec<u8> = FromHex::from_hex("ffffffff48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5d182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b61626300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000001").unwrap();
        let expected:Vec<u8> =  FromHex::from_hex("fc59093aafa9ab43daae0e914c57635c5402d8e3d2130eb9b3cc181de7f0ecf9b22bf99a7815ce16419e200e01846e6b5df8cc7703041bbceb571de6631d2615").unwrap();
        let mut out = [0u8; 64];
        blake2
            .execute(&input[..], &mut BytesRef::Fixed(&mut out[..]))
            .unwrap();
        assert_eq!(&out[..], &expected[..]);
    }
}
