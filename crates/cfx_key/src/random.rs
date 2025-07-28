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

use super::{KeyPair, KeyPairGenerator, SECP256K1};
use rand_07::rngs::OsRng;

/// Randomly generates new keypair, instantiating the RNG each time.
pub struct Random;

impl KeyPairGenerator for Random {
    type Error = ::std::io::Error;

    fn generate(&mut self) -> Result<KeyPair, Self::Error> {
        match OsRng.generate() {
            Ok(pair) => Ok(pair),
            Err(void) => match void {}, // LLVM unreachable
        }
    }
}

impl KeyPairGenerator for OsRng {
    type Error = crate::Void;

    fn generate(&mut self) -> Result<KeyPair, Self::Error> {
        let (sec, publ) = SECP256K1
            .generate_keypair(self)
            .expect("context always created with full capabilities; qed");

        Ok(KeyPair::from_keypair(sec, publ))
    }
}
