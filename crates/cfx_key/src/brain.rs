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

use super::{KeyPair, KeyPairGenerator, Secret};
use cfx_crypto::crypto::keccak::Keccak256;
use log::trace;
use parity_wordlist;

/// Simple brainwallet.
pub struct Brain(String);

impl Brain {
    pub fn new(s: String) -> Self { Brain(s) }

    pub fn validate_phrase(
        phrase: &str, expected_words: usize,
    ) -> Result<(), crate::WordlistError> {
        parity_wordlist::validate_phrase(phrase, expected_words)
    }
}

impl KeyPairGenerator for Brain {
    type Error = crate::Void;

    fn generate(&mut self) -> Result<KeyPair, Self::Error> {
        let seed = self.0.clone();
        let mut secret = seed.into_bytes().keccak256();

        let mut i = 0;
        loop {
            secret = secret.keccak256();

            match i > 16384 {
                false => i += 1,
                true => {
                    if let Ok(pair) = Secret::from_unsafe_slice(&secret)
                        .and_then(KeyPair::from_secret)
                    {
                        if pair.address()[0] == 0x10 {
                            trace!(
                                "Testing: {}, got: {:?}",
                                self.0,
                                pair.address()
                            );
                            return Ok(pair);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Brain, KeyPairGenerator};
    use std::str::FromStr;

    #[test]
    fn test_brain() {
        let words = "this is sparta!".to_owned();
        let first_keypair = Brain::new(words.clone()).generate().unwrap();
        let second_keypair = Brain::new(words).generate().unwrap();
        assert_eq!(first_keypair.secret(), second_keypair.secret());
    }

    // Brain-wallet compatibility guard for the parity-wordlist swap
    // (paritytech/wordlist -> Conflux-Chain/conflux-parity-deps fork at
    // rand 0.9). If the 7530-word dictionary ever drifts, or if the brain
    // key-derivation (keccak chain -> secret) changes, this test fails and
    // anyone's previously-generated brain wallets would become unrecoverable.
    #[test]
    fn brain_wallet_compat_fixed_phrase() {
        // All twelve words are taken from the original parity-wordlist
        // dictionary, so validate_phrase must accept the phrase.
        let phrase = "abacus abdomen ability able abnormal absence \
                      absolute abstract accent accurate accustom acorn"
            .to_owned();
        Brain::validate_phrase(&phrase, 12)
            .expect("phrase is all dictionary words");

        // Derivation is deterministic (double-keccak chain until the address
        // has the 0x10 type nibble), so a hardcoded secret pins both the
        // hash path and the dictionary-word inputs.
        let kp = Brain::new(phrase).generate().unwrap();
        let expected = crate::Secret::from_str(
            "0ae3b9521d5bc321284646b6b7ed286223d6630b5092ec795a9ca31884a81442",
        )
        .unwrap();
        assert_eq!(kp.secret(), &expected);
    }
}
