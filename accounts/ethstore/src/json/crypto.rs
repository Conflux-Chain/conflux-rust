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

use super::{
    Bytes, Cipher, CipherSer, CipherSerParams, Kdf, KdfSer, KdfSerParams, H256,
};
use serde::{
    de::{Error, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_json;
use std::{fmt, str};

pub type CipherText = Bytes;

#[derive(Debug, PartialEq)]
pub struct Crypto {
    pub cipher: Cipher,
    pub ciphertext: CipherText,
    pub kdf: Kdf,
    pub mac: H256,
}

impl str::FromStr for Crypto {
    type Err = serde_json::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> { serde_json::from_str(s) }
}

impl From<Crypto> for String {
    fn from(c: Crypto) -> Self {
        serde_json::to_string(&c).expect(
            "Serialization cannot fail, because all crypto keys are strings",
        )
    }
}

enum CryptoField {
    Cipher,
    CipherParams,
    CipherText,
    Kdf,
    KdfParams,
    Mac,
    Version,
}

impl<'a> Deserialize<'a> for CryptoField {
    fn deserialize<D>(deserializer: D) -> Result<CryptoField, D::Error>
    where D: Deserializer<'a> {
        deserializer.deserialize_any(CryptoFieldVisitor)
    }
}

struct CryptoFieldVisitor;

impl<'a> Visitor<'a> for CryptoFieldVisitor {
    type Value = CryptoField;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a valid crypto struct description")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: Error {
        match value {
            "cipher" => Ok(CryptoField::Cipher),
            "cipherparams" => Ok(CryptoField::CipherParams),
            "ciphertext" => Ok(CryptoField::CipherText),
            "kdf" => Ok(CryptoField::Kdf),
            "kdfparams" => Ok(CryptoField::KdfParams),
            "mac" => Ok(CryptoField::Mac),
            "version" => Ok(CryptoField::Version),
            _ => Err(Error::custom(format!("Unknown field: '{}'", value))),
        }
    }
}

impl<'a> Deserialize<'a> for Crypto {
    fn deserialize<D>(deserializer: D) -> Result<Crypto, D::Error>
    where D: Deserializer<'a> {
        static FIELDS: &'static [&'static str] =
            &["id", "version", "crypto", "Crypto", "address"];
        deserializer.deserialize_struct("Crypto", FIELDS, CryptoVisitor)
    }
}

struct CryptoVisitor;

impl<'a> Visitor<'a> for CryptoVisitor {
    type Value = Crypto;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a valid vault crypto object")
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where V: MapAccess<'a> {
        let mut cipher = None;
        let mut cipherparams = None;
        let mut ciphertext = None;
        let mut kdf = None;
        let mut kdfparams = None;
        let mut mac = None;

        loop {
            match visitor.next_key()? {
                Some(CryptoField::Cipher) => {
                    cipher = Some(visitor.next_value()?);
                }
                Some(CryptoField::CipherParams) => {
                    cipherparams = Some(visitor.next_value()?);
                }
                Some(CryptoField::CipherText) => {
                    ciphertext = Some(visitor.next_value()?);
                }
                Some(CryptoField::Kdf) => {
                    kdf = Some(visitor.next_value()?);
                }
                Some(CryptoField::KdfParams) => {
                    kdfparams = Some(visitor.next_value()?);
                }
                Some(CryptoField::Mac) => {
                    mac = Some(visitor.next_value()?);
                }
                // skip not required version field (it appears in pyethereum
                // generated keystores)
                Some(CryptoField::Version) => {
                    visitor.next_value().unwrap_or(())
                }
                None => {
                    break;
                }
            }
        }

        let cipher = match (cipher, cipherparams) {
            (
                Some(CipherSer::Aes128Ctr),
                Some(CipherSerParams::Aes128Ctr(params)),
            ) => Cipher::Aes128Ctr(params),
            (None, _) => return Err(V::Error::missing_field("cipher")),
            (Some(_), None) => {
                return Err(V::Error::missing_field("cipherparams"))
            }
        };

        let ciphertext = match ciphertext {
            Some(ciphertext) => ciphertext,
            None => return Err(V::Error::missing_field("ciphertext")),
        };

        let kdf = match (kdf, kdfparams) {
            (Some(KdfSer::Pbkdf2), Some(KdfSerParams::Pbkdf2(params))) => {
                Kdf::Pbkdf2(params)
            }
            (Some(KdfSer::Scrypt), Some(KdfSerParams::Scrypt(params))) => {
                Kdf::Scrypt(params)
            }
            (Some(_), Some(_)) => {
                return Err(V::Error::custom("Invalid cipherparams"))
            }
            (None, _) => return Err(V::Error::missing_field("kdf")),
            (Some(_), None) => {
                return Err(V::Error::missing_field("kdfparams"))
            }
        };

        let mac = match mac {
            Some(mac) => mac,
            None => return Err(V::Error::missing_field("mac")),
        };

        let result = Crypto {
            cipher,
            ciphertext,
            kdf,
            mac,
        };

        Ok(result)
    }
}

impl Serialize for Crypto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let mut crypto = serializer.serialize_struct("Crypto", 6)?;
        match self.cipher {
            Cipher::Aes128Ctr(ref params) => {
                crypto.serialize_field("cipher", &CipherSer::Aes128Ctr)?;
                crypto.serialize_field("cipherparams", params)?;
            }
        }
        crypto.serialize_field("ciphertext", &self.ciphertext)?;
        match self.kdf {
            Kdf::Pbkdf2(ref params) => {
                crypto.serialize_field("kdf", &KdfSer::Pbkdf2)?;
                crypto.serialize_field("kdfparams", params)?;
            }
            Kdf::Scrypt(ref params) => {
                crypto.serialize_field("kdf", &KdfSer::Scrypt)?;
                crypto.serialize_field("kdfparams", params)?;
            }
        }

        crypto.serialize_field("mac", &self.mac)?;
        crypto.end()
    }
}
