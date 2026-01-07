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

use crate::{KeyPair, RandomKeyPairGenerator, SecretKey, SECP256K1};
use std::io;
use subtle::ConstantTimeEq;

pub const KEY_LENGTH: usize = 32;
pub const KEY_ITERATIONS: usize = 10240;
pub const KEY_LENGTH_AES: usize = KEY_LENGTH / 2;

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
    use super::{Error, SecretKey, SECP256K1};
    use secp256k1::{self, ecdh, key};

    /// Agree on a shared secret
    pub fn agree<S, P>(secret: &S, public: &P) -> Result<S, Error>
    where
        S: SecretKey,
        P: AsRef<[u8]>,
    {
        let context = &SECP256K1;
        let pdata = {
            let mut temp = [4u8; 65];
            let pub_bytes = public.as_ref();
            if pub_bytes.len() < 64 {
                return Err(Error::Secp(secp256k1::Error::InvalidPublicKey));
            }
            (&mut temp[1..65]).copy_from_slice(&pub_bytes[0..64]);
            temp
        };

        let publ = key::PublicKey::from_slice(context, &pdata)?;
        let sec = key::SecretKey::from_slice(context, secret.as_ref())?;
        let shared = ecdh::SharedSecret::new_raw(context, &publ, &sec);

        S::from_unsafe_slice(&shared[0..32])
            .map_err(|_| Error::Secp(secp256k1::Error::InvalidSecretKey))
    }
}

/// ECIES function
pub mod ecies {
    use super::{
        ecdh, is_equal, Error, KeyPair, RandomKeyPairGenerator, SecretKey,
    };
    use cfx_types::H128;
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

    /// Encrypt a message with a public key, writing an HMAC covering both
    /// the plaintext and authenticated data.
    ///
    /// Authenticated data may be empty.
    pub fn encrypt<G, KP, S, P>(
        generator: &mut G, public: &P, auth_data: &[u8], plain: &[u8],
    ) -> Result<Vec<u8>, Error>
    where
        G: RandomKeyPairGenerator<KeyPair = KP, Error = std::io::Error>,
        KP: KeyPair<Secret = S, Public = P>,
        S: SecretKey,
        P: AsRef<[u8]>,
    {
        let r = generator.generate()?;
        let z = ecdh::agree(r.secret(), public)?;
        let mut key = [0u8; 32];
        kdf(&z, &[0u8; 0], &mut key);

        let ekey = &key[0..16];
        let mkey = Sha256::digest(&key[16..32]);

        let mut msg = vec![0u8; 1 + 64 + 16 + plain.len() + 32];
        msg[0] = 0x04u8;
        {
            let msgd = &mut msg[1..];
            let pub_bytes = r.public().as_ref();
            if pub_bytes.len() < 64 {
                return Err(Error::InvalidMessage);
            }
            msgd[0..64].copy_from_slice(&pub_bytes[0..64]);
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
    pub fn decrypt<S>(
        secret: &S, auth_data: &[u8], encrypted: &[u8],
    ) -> Result<Vec<u8>, Error>
    where S: SecretKey {
        let meta_len = 1 + 64 + 16 + 32;
        if encrypted.len() < meta_len || encrypted[0] < 2 || encrypted[0] > 4 {
            return Err(Error::InvalidMessage); //invalid message: publickey
        }

        let e = &encrypted[1..];
        // Extract public key bytes directly - use a fixed-size array reference
        let mut pub_array = [0u8; 64];
        pub_array.copy_from_slice(&e[0..64]);
        let z = ecdh::agree(secret, &pub_array)?;
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

    fn kdf<S: SecretKey>(secret: &S, s1: &[u8], dest: &mut [u8]) {
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
            hasher.update(secret.as_ref());
            hasher.update(s1);
            let d = hasher.finalize();
            dest[written..(written + 32)].copy_from_slice(&d);
            written += 32;
            ctr += 1;
        }
    }
}

pub mod aes {
    use super::Error;
    use aes::Aes128;
    use cbc::{cipher::BlockDecryptMut, Decryptor};
    use ctr::{
        cipher::{KeyIvInit as CtrKeyIvInit, StreamCipher},
        Ctr128BE,
    };

    type Aes128Ctr = Ctr128BE<Aes128>;
    type Aes128CbcDec = Decryptor<Aes128>;

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

    pub fn decrypt_128_cbc<'a>(
        key: &[u8], iv: &[u8], data: &[u8], dest: &'a mut [u8],
    ) -> Result<&'a [u8], String> {
        if key.len() != 16 {
            return Err("Key must be exactly 16 bytes for AES-128".to_string());
        }

        if iv.len() != 16 {
            return Err("IV must be exactly 16 bytes".to_string());
        }

        if data.is_empty() {
            return Err("Data cannot be empty".to_string());
        }

        if data.len() % 16 != 0 {
            return Err(
                "Data length must be a multiple of 16 bytes".to_string()
            );
        }

        // Create decryptor
        let decryptor = Aes128CbcDec::new(key.into(), iv.into());
        dest[..data.len()].copy_from_slice(data);

        // Decrypt and remove PKCS7 padding
        let plaintext = decryptor
            .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(dest)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(plaintext)
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

pub mod scrypt {
    use super::{KEY_LENGTH, KEY_LENGTH_AES};
    use scrypt::{errors, scrypt, Params};

    pub fn derive_key(
        pass: &[u8], salt: &[u8], n: u32, p: u32, r: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        // sanity checks
        let log_n = (32 - n.leading_zeros() - 1) as u8;
        if log_n as u32 >= r * 16 {
            return Err(errors::InvalidParams.to_string());
        }

        if p as u64 > ((u32::MAX as u64 - 1) * 32) / (128 * (r as u64)) {
            return Err(errors::InvalidParams.to_string());
        }

        let mut derived_key = vec![0u8; KEY_LENGTH];
        let scrypt_params =
            Params::new(log_n, r, p, KEY_LENGTH).map_err(|e| e.to_string())?;
        scrypt(pass, salt, &scrypt_params, &mut derived_key)
            .map_err(|e| e.to_string())?;
        let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
        let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
        Ok((derived_right_bits.to_vec(), derived_left_bits.to_vec()))
    }
}

pub mod pbkdf2 {
    use super::{KEY_LENGTH, KEY_LENGTH_AES};
    use hmac;
    use pbkdf2;
    use sha2;

    pub struct Salt<'a>(pub &'a [u8]);
    pub struct Secret<'a>(pub &'a [u8]);

    pub fn sha256(
        iter: u32, salt: Salt<'_>, sec: Secret<'_>, out: &mut [u8; 32],
    ) -> Result<(), String> {
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(sec.0, salt.0, iter, out)
            .map_err(|e| e.to_string())
    }

    pub fn sha512(
        iter: u32, salt: Salt<'_>, sec: Secret<'_>, out: &mut [u8; 64],
    ) -> Result<(), String> {
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(sec.0, salt.0, iter, out)
            .map_err(|e| e.to_string())
    }

    pub fn derive_key_iterations(
        password: &[u8], salt: &[u8], c: u32,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut derived_key = [0u8; KEY_LENGTH];
        sha256(c, Salt(salt), Secret(password), &mut derived_key)?;
        let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
        let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
        Ok((derived_right_bits.to_vec(), derived_left_bits.to_vec()))
    }
}

pub mod digest {
    use std::{marker::PhantomData, ops::Deref};

    use digest::generic_array::{
        typenum::{U20, U32, U64},
        GenericArray,
    };
    use ripemd;
    use sha2::Digest as RDigest;

    /// The message digest.
    pub struct Digest<T>(InnerDigest, PhantomData<T>);

    enum InnerDigest {
        Sha256(GenericArray<u8, U32>),
        Sha512(GenericArray<u8, U64>),
        Ripemd160(GenericArray<u8, U20>),
    }

    impl<T> Deref for Digest<T> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            match self.0 {
                InnerDigest::Sha256(ref d) => &d[..],
                InnerDigest::Sha512(ref d) => &d[..],
                InnerDigest::Ripemd160(ref d) => &d[..],
            }
        }
    }

    /// Single-step sha256 digest computation.
    pub fn sha256(data: &[u8]) -> Digest<Sha256> {
        let mut hasher = Hasher::sha256();
        hasher.update(data);
        hasher.finish()
    }

    /// Single-step sha512 digest computation.
    pub fn sha512(data: &[u8]) -> Digest<Sha512> {
        let mut hasher = Hasher::sha512();
        hasher.update(data);
        hasher.finish()
    }

    /// Single-step ripemd160 digest computation.
    pub fn ripemd160(data: &[u8]) -> Digest<Ripemd160> {
        let mut hasher = Hasher::ripemd160();
        hasher.update(data);
        hasher.finish()
    }

    #[derive(Debug)]
    pub enum Sha256 {}
    #[derive(Debug)]
    pub enum Sha512 {}
    #[derive(Debug)]
    pub enum Ripemd160 {}

    /// Stateful digest computation.
    pub struct Hasher<T>(Inner, PhantomData<T>);

    enum Inner {
        Sha256(sha2::Sha256),
        Sha512(sha2::Sha512),
        Ripemd160(ripemd::Ripemd160),
    }

    impl Hasher<Sha256> {
        pub fn sha256() -> Hasher<Sha256> {
            Hasher(Inner::Sha256(sha2::Sha256::default()), PhantomData)
        }
    }

    impl Hasher<Sha512> {
        pub fn sha512() -> Hasher<Sha512> {
            Hasher(Inner::Sha512(sha2::Sha512::default()), PhantomData)
        }
    }

    impl Hasher<Ripemd160> {
        pub fn ripemd160() -> Hasher<Ripemd160> {
            Hasher(Inner::Ripemd160(ripemd::Ripemd160::default()), PhantomData)
        }
    }

    impl<T> Hasher<T> {
        pub fn update(&mut self, data: &[u8]) {
            match self.0 {
                Inner::Sha256(ref mut ctx) => ctx.update(data),
                Inner::Sha512(ref mut ctx) => ctx.update(data),
                Inner::Ripemd160(ref mut ctx) => ctx.update(data),
            }
        }

        pub fn finish(self) -> Digest<T> {
            match self.0 {
                Inner::Sha256(ctx) => {
                    Digest(InnerDigest::Sha256(ctx.finalize()), PhantomData)
                }
                Inner::Sha512(ctx) => {
                    Digest(InnerDigest::Sha512(ctx.finalize()), PhantomData)
                }
                Inner::Ripemd160(ctx) => {
                    Digest(InnerDigest::Ripemd160(ctx.finalize()), PhantomData)
                }
            }
        }
    }
}

pub fn derive_mac(derived_left_bits: &[u8], cipher_text: &[u8]) -> Vec<u8> {
    let mut mac = vec![0u8; KEY_LENGTH_AES + cipher_text.len()];
    mac[0..KEY_LENGTH_AES].copy_from_slice(derived_left_bits);
    mac[KEY_LENGTH_AES..cipher_text.len() + KEY_LENGTH_AES]
        .copy_from_slice(cipher_text);
    mac
}

pub fn is_equal(a: &[u8], b: &[u8]) -> bool { a.ct_eq(b).into() }
