use super::Pricer;
use cfx_types::U256;
use std::convert::TryInto;

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
