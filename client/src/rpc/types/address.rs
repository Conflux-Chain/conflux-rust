// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_addr::{
    cfx_addr_decode, cfx_addr_encode, DecodingError, EncodingOptions, Network,
    UserAddress,
};
use cfx_types::H160;
use parking_lot::RwLock;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    convert::{TryFrom, TryInto},
    ops::Deref,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address(pub UserAddress);

lazy_static! {
    pub static ref FORCE_BASE32_ADDRESS: RwLock<bool> = RwLock::new(true);
    pub static ref NODE_NETWORK: RwLock<Network> = RwLock::new(Network::Main);
}

// TODO: remove this function.
#[cfg(test)]
pub fn force_base32_address() { *FORCE_BASE32_ADDRESS.write() = true; }

#[cfg(test)]
pub fn disable_base32_address() { *FORCE_BASE32_ADDRESS.write() = false; }

#[derive(Clone, Debug, PartialEq)]
pub struct RpcAddress {
    pub hex_address: H160,
    pub network: Network,
}

impl Deref for Address {
    type Target = UserAddress;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl TryInto<H160> for Address {
    type Error = String;

    fn try_into(self) -> Result<H160, Self::Error> {
        match self.hex {
            Some(h) => Ok(h),
            None => Err("Not a hex address".into()),
        }
    }
}

impl Address {
    pub fn try_from_h160(addr: H160, network: Network) -> Result<Self, String> {
        // TODO: is there a simpler way?
        let addr_str =
            cfx_addr_encode(&addr.0, network, EncodingOptions::Simple)
                .map_err(|e| e.to_string())?;
        let user_addr =
            cfx_addr_decode(&addr_str).map_err(|e| e.to_string())?;
        assert_eq!(user_addr.hex, Some(addr));
        Ok(Address(user_addr))
    }

    pub fn null(network: Network) -> Result<Self, String> {
        Self::try_from_h160(H160::default(), network)
    }
}

impl TryFrom<&str> for Address {
    type Error = DecodingError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let inner = cfx_addr_decode(raw)?;
        Ok(Address(inner))
    }
}

impl From<RpcAddress> for H160 {
    fn from(x: RpcAddress) -> Self { x.hex_address }
}

impl<'a> Deserialize<'a> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'a> {
        if *FORCE_BASE32_ADDRESS.read() {
            let s: String = Deserialize::deserialize(deserializer)?;

            let inner = cfx_addr_decode(&s).map_err(|e| {
                de::Error::custom(format!("Invalid base32 address: {}", e))
            })?;

            Ok(Address(inner))
        } else {
            Ok(Address(UserAddress {
                base32: "".into(),
                bytes: vec![],
                hex: Deserialize::deserialize(deserializer)?,
                network: *NODE_NETWORK.read(),
            }))
        }
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if *FORCE_BASE32_ADDRESS.read() {
            let addr_str = cfx_addr_encode(
                &self.bytes[..],
                self.network,
                EncodingOptions::QrCode,
            )
            .map_err(|e| {
                ser::Error::custom(format!("Failed to encode address: {}", e))
            })?;

            serializer.serialize_str(&addr_str)
        } else {
            // TODO: remove this
            if let Some(hex) = self.hex {
                serializer.serialize_str(&format!("{:?}", hex))
            } else {
                serializer.serialize_none()
            }
        }
    }
}

impl<'a> Deserialize<'a> for RpcAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'a> {
        if *FORCE_BASE32_ADDRESS.read() {
            let s: String = Deserialize::deserialize(deserializer)?;

            let parsed_address = cfx_addr_decode(&s).map_err(|e| {
                de::Error::custom(format!("Invalid base32 address: {}", e))
            })?;

            Ok(RpcAddress {
                hex_address: parsed_address.hex.ok_or_else(|| {
                    de::Error::custom(
                        "Invalid base32 address: not a SIZE_160 address.",
                    )
                })?,
                network: parsed_address.network,
            })
        } else {
            // TODO: remove this
            Ok(Self {
                hex_address: Deserialize::deserialize(deserializer)?,
                network: *NODE_NETWORK.read(),
            })
        }
    }
}

impl Serialize for RpcAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let addr_str = cfx_addr_encode(
            self.hex_address.as_bytes(),
            self.network,
            EncodingOptions::QrCode,
        )
        .map_err(|e| {
            ser::Error::custom(format!("Failed to encode address: {}", e))
        })?;

        serializer.serialize_str(&addr_str)
    }
}

#[cfg(test)]
mod tests {
    use super::{force_base32_address, Address};
    use cfx_addr::Network;
    use serde_json;
    use serial_test::serial;
    use std::convert::TryInto;

    fn check_deserialize(raw: &str, hex: &str, network: Network) {
        let addr_hex = hex.trim_start_matches("0x").parse().unwrap();
        let parsed: Address = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.network, network);
        assert_eq!(parsed.hex, Some(addr_hex));
        assert_eq!(parsed.try_into(), Ok(addr_hex));
    }

    #[test]
    #[serial] // TODO: remove
    fn test_deserialize_address() {
        force_base32_address();

        check_deserialize(
            "\"cfx:022xg0j5vg1fba4nh7gz372we6740puptms36cm58c\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );

        check_deserialize(
            "\"cfxtest:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Test,
        );

        check_deserialize(
            "\"cfxtest:type.contract:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Test,
        );
    }

    #[test]
    #[should_panic]
    #[serial] // TODO: remove
    fn test_deserialize_incorrect_network_prefix() {
        force_base32_address();

        check_deserialize(
            "\"cfy:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    #[serial] // TODO: remove
    fn test_deserialize_no_network_prefix() {
        force_base32_address();

        check_deserialize(
            "\"022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    #[serial] // TODO: remove
    fn test_deserialize_incorrect_type() {
        force_base32_address();

        check_deserialize(
            "\"cfx:type.user:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    #[serial] // TODO: remove
    fn test_deserialize_incorrect_checksum() {
        force_base32_address();

        check_deserialize(
            "\"cfx:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc7\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }
}
