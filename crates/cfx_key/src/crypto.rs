// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.
//
// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2020 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Re-export everything from cfx_crypto for compatibility
pub use cfx_crypto::crypto::*;

// Re-export constants
pub use cfx_crypto::crypto::{KEY_ITERATIONS, KEY_LENGTH, KEY_LENGTH_AES};

pub mod ecies {
    use super::Error;
    use crate::{Public, Random, Secret};

    /// Encrypt a message with a public key, writing an HMAC covering both
    /// the plaintext and authenticated data.
    ///
    /// Authenticated data may be empty.
    pub fn encrypt(
        public: &Public, auth_data: &[u8], plain: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut generator = Random;
        cfx_crypto::crypto::ecies::encrypt(
            &mut generator,
            public,
            auth_data,
            plain,
        )
    }

    /// Decrypt a message with a secret key, checking HMAC for ciphertext
    /// and authenticated data validity.
    pub fn decrypt(
        secret: &Secret, auth_data: &[u8], encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        cfx_crypto::crypto::ecies::decrypt(secret, auth_data, encrypted)
    }
}

#[cfg(test)]
mod tests {
    use super::{ecdh, ecies};
    use crate::{
        crypto::scrypt::derive_key, KeyPairGenerator, Public, Random, Secret,
    };
    use std::{io::Error, str::FromStr};

    #[test]
    fn ecies_shared() {
        let kp = Random.generate().unwrap();
        let message = b"So many books, so little time";

        let shared = b"shared";
        let wrong_shared = b"incorrect";
        let encrypted = ecies::encrypt(kp.public(), shared, message).unwrap();
        assert_ne!(encrypted[..], message[..]);
        assert_eq!(encrypted[0], 0x04);

        assert!(ecies::decrypt(kp.secret(), wrong_shared, &encrypted).is_err());
        let decrypted =
            ecies::decrypt(kp.secret(), shared, &encrypted).unwrap();
        assert_eq!(decrypted[..message.len()], message[..]);
    }

    #[test]
    fn ecdh_agree() {
        /*
        kp1: KeyPair { secret: 0x3d6c3a910832105febef6f8111b51b11e6cb190fb45b5fc70ee6290c411e9a09, public: 0x057c7d5b963cb4605c3e0c4d5cbefd2a31fb3877e481172d6225a77e0a5964a0112f123aaee2d42f6bec55b396564ffcbd188c799f905253c9394642447063b0 }
        kp2: KeyPair { secret: 0x6da0008f5531966a9637266fd180ca66e2643920a2d60d4c34350e25f0ccda98, public: 0x4cf74522f3c86d88cd2ba56b378d3fccd4ba3fe93fe4e11ebecc24b06085fc37ee63073aa998693cf2573dc9a437ac0a94d9093054419d23390bad2329ee5eee }
         */
        let secret = Secret::from_str(
            "3d6c3a910832105febef6f8111b51b11e6cb190fb45b5fc70ee6290c411e9a09",
        )
        .unwrap();
        let publ = Public::from_str("4cf74522f3c86d88cd2ba56b378d3fccd4ba3fe93fe4e11ebecc24b06085fc37ee63073aa998693cf2573dc9a437ac0a94d9093054419d23390bad2329ee5eee").unwrap();

        let agree_secret = ecdh::agree(&secret, &publ).unwrap();

        let expected = Secret::from_str(
            "c6440592fa14256dbbc39639b77524e51bac84b64fa1b1726130a49263f1fb6f",
        )
        .unwrap();
        assert_eq!(agree_secret, expected);
    }
    // test is build from previous crypto lib behaviour, values may be incorrect
    // if previous crypto lib got a bug.
    #[test]
    pub fn test_derive() -> Result<(), Error> {
        let pass = [109, 121, 112, 97, 115, 115, 10];
        let salt = [
            109, 121, 115, 97, 108, 116, 115, 104, 111, 117, 108, 100, 102,
            105, 108, 108, 115, 111, 109, 109, 101, 98, 121, 116, 101, 108,
            101, 110, 103, 116, 104, 10,
        ];
        let r1 = [
            93, 134, 79, 68, 223, 27, 44, 174, 236, 184, 179, 203, 74, 139, 73,
            66,
        ];
        let r2 = [
            2, 24, 239, 131, 172, 164, 18, 171, 132, 207, 22, 217, 150, 20,
            203, 37,
        ];
        let l1 = [
            6, 90, 119, 45, 67, 2, 99, 151, 81, 88, 166, 210, 244, 19, 123, 208,
        ];
        let l2 = [
            253, 123, 132, 12, 188, 89, 196, 2, 107, 224, 239, 231, 135, 177,
            125, 62,
        ];

        let (l, r) = derive_key(&pass[..], &salt, 262, 1, 8).unwrap();
        assert_eq!(l, r1);
        assert_eq!(r, l1);
        let (l, r) = derive_key(&pass[..], &salt, 144, 4, 4).unwrap();
        assert_eq!(l, r2);
        assert_eq!(r, l2);
        Ok(())
    }
}
