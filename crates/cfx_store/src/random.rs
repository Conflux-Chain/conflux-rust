// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use rand::{distr::Alphanumeric, rngs::OsRng, Rng, TryRngCore};

pub trait Random {
    fn random() -> Self
    where Self: Sized;
}

impl Random for [u8; 16] {
    fn random() -> Self {
        let mut result = [0u8; 16];
        OsRng.try_fill_bytes(&mut result).unwrap();
        result
    }
}

impl Random for [u8; 32] {
    fn random() -> Self {
        let mut result = [0u8; 32];
        OsRng.try_fill_bytes(&mut result).unwrap();
        result
    }
}

/// Generate a random string of given length.
pub fn random_string(length: usize) -> String {
    let mut rng = rand::rng();
    (&mut rng)
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}
