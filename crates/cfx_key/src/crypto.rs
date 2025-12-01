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

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secp256k1 error: {0}")]
    Secp(#[from] secp256k1::Error),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid message")]
    InvalidMessage,
    #[error("aes error")]
    Aes,
}

/// ECDH functions
pub mod ecdh {
    use super::Error;
    use crate::{Public, Secret, SECP256K1};
    use secp256k1::{self, ecdh, key};

    /// Agree on a shared secret
    pub fn agree(secret: &Secret, public: &Public) -> Result<Secret, Error> {
        let context = &SECP256K1;
        let pdata = {
            let mut temp = [4u8; 65];
            (&mut temp[1..65]).copy_from_slice(&public[0..64]);
            temp
        };

        let publ = key::PublicKey::from_slice(context, &pdata)?;
        let sec = key::SecretKey::from_slice(context, secret.as_bytes())?;
        let shared = ecdh::SharedSecret::new_raw(context, &publ, &sec);

        Secret::from_unsafe_slice(&shared[0..32])
            .map_err(|_| Error::Secp(secp256k1::Error::InvalidSecretKey))
    }
}

/// ECIES function
pub mod ecies {
    use super::{ecdh, Error};
    use crate::{KeyPairGenerator, Public, Random, Secret};
    use cfx_types::H128;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    /// Encrypt a message with a public key, writing an HMAC covering both
    /// the plaintext and authenticated data.
    ///
    /// Authenticated data may be empty.
    pub fn encrypt(
        public: &Public, auth_data: &[u8], plain: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let r = Random.generate()?;
        let z = ecdh::agree(r.secret(), public)?;
        let mut key = [0u8; 32];
        kdf(&z, &[0u8; 0], &mut key);

        let ekey = &key[0..16];
        let mkey = Sha256::digest(&key[16..32]);

        let mut msg = vec![0u8; 1 + 64 + 16 + plain.len() + 32];
        msg[0] = 0x04u8;
        {
            let msgd = &mut msg[1..];
            msgd[0..64].copy_from_slice(r.public().as_bytes());
            let iv = H128::random();
            msgd[64..80].copy_from_slice(iv.as_bytes());
            {
                let cipher = &mut msgd[(64 + 16)..(64 + 16 + plain.len())];
                super::aes::encrypt_128_ctr(
                    ekey,
                    iv.as_bytes(),
                    plain,
                    cipher,
                )?;
            }
            let mut hmac = HmacSha256::new_from_slice(mkey.as_slice())
                .expect("output of Sha256 has invalid length");
            {
                let cipher_iv = &msgd[64..(64 + 16 + plain.len())];
                hmac.update(cipher_iv);
            }
            hmac.update(auth_data);
            let sig = hmac.finalize().into_bytes();
            msgd[(64 + 16 + plain.len())..].copy_from_slice(&sig);
        }
        Ok(msg)
    }

    /// Decrypt a message with a secret key, checking HMAC for ciphertext
    /// and authenticated data validity.
    pub fn decrypt(
        secret: &Secret, auth_data: &[u8], encrypted: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let meta_len = 1 + 64 + 16 + 32;
        if encrypted.len() < meta_len || encrypted[0] < 2 || encrypted[0] > 4 {
            return Err(Error::InvalidMessage); //invalid message: publickey
        }

        let e = &encrypted[1..];
        let p = Public::from_slice(&e[0..64]);
        let z = ecdh::agree(secret, &p)?;
        let mut key = [0u8; 32];
        kdf(&z, &[0u8; 0], &mut key);

        let ekey = &key[0..16];
        let mkey = Sha256::digest(&key[16..32]);

        let clen = encrypted.len() - meta_len;
        let cipher_with_iv = &e[64..(64 + 16 + clen)];
        let cipher_iv = &cipher_with_iv[0..16];
        let cipher_no_iv = &cipher_with_iv[16..];
        let msg_mac = &e[(64 + 16 + clen)..];

        // Verify tag
        let mut hmac = HmacSha256::new_from_slice(mkey.as_slice())
            .expect("output of Sha256 has invalid length");
        hmac.update(cipher_with_iv);
        hmac.update(auth_data);
        let mac = hmac.finalize().into_bytes();

        if !is_equal(mac.as_slice(), msg_mac) {
            return Err(Error::InvalidMessage);
        }

        let mut msg = vec![0u8; clen];
        super::aes::decrypt_128_ctr(
            ekey,
            cipher_iv,
            cipher_no_iv,
            &mut msg[..],
        )?;
        Ok(msg)
    }

    fn kdf(secret: &Secret, s1: &[u8], dest: &mut [u8]) {
        // SEC/ISO/Shoup specify counter size SHOULD be equivalent
        // to size of hash output, however, it also notes that
        // the 4 bytes is okay. NIST specifies 4 bytes.
        let mut ctr = 1u32;
        let mut written = 0usize;
        while written < dest.len() {
            let mut hasher = Sha256::new();
            let ctrs = [
                (ctr >> 24) as u8,
                (ctr >> 16) as u8,
                (ctr >> 8) as u8,
                ctr as u8,
            ];
            hasher.update(&ctrs);
            hasher.update(secret.as_bytes());
            hasher.update(s1);
            let d = hasher.finalize();
            dest[written..(written + 32)].copy_from_slice(&d);
            written += 32;
            ctr += 1;
        }
    }

    fn is_equal(a: &[u8], b: &[u8]) -> bool { a.ct_eq(b).into() }
}

mod aes {
    use super::Error;
    use aes::Aes128;
    use ctr::{
        cipher::{KeyIvInit, StreamCipher},
        Ctr128BE,
    };

    type Aes128Ctr = Ctr128BE<Aes128>;

    pub fn encrypt_128_ctr(
        key: &[u8], iv: &[u8], plain: &[u8], ciphertext: &mut [u8],
    ) -> Result<(), Error> {
        let mut cipher = Aes128Ctr::new(key.into(), iv.into());
        ciphertext[..plain.len()].copy_from_slice(plain);
        cipher
            .try_apply_keystream(ciphertext)
            .map_err(|_| Error::Aes)?;
        Ok(())
    }

    pub fn decrypt_128_ctr(
        key: &[u8], iv: &[u8], ciphertext: &[u8], plain: &mut [u8],
    ) -> Result<(), Error> {
        let mut cipher = Aes128Ctr::new(key.into(), iv.into());
        plain[..ciphertext.len()].copy_from_slice(ciphertext);
        cipher.try_apply_keystream(plain).map_err(|_| Error::Aes)?;
        Ok(())
    }
}

pub mod keccak {
    use tiny_keccak::{Hasher, Keccak};

    pub trait Keccak256<T> {
        fn keccak256(&self) -> T
        where T: Sized;
    }

    impl<T> Keccak256<[u8; 32]> for T
    where T: AsRef<[u8]>
    {
        fn keccak256(&self) -> [u8; 32] {
            let mut keccak = Keccak::v256();
            let mut result = [0u8; 32];
            keccak.update(self.as_ref());
            keccak.finalize(&mut result);
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ecdh, ecies};
    use crate::{KeyPairGenerator, Public, Random, Secret};
    use std::str::FromStr;

    #[test]
    fn ecies_shared() {
        let kp = Random.generate().unwrap();
        let message = b"So many books, so little time";

        let shared = b"shared";
        let wrong_shared = b"incorrect";
        let encrypted = ecies::encrypt(kp.public(), shared, message).unwrap();
        assert!(encrypted[..] != message[..]);
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
}
