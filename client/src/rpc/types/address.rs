// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_addr::{cfx_addr_decode, cfx_addr_encode, UserAddress};
use cfx_types::H160;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use std::{convert::TryInto, ops::Deref};

#[derive(Debug)]
pub struct Address(UserAddress);

impl Deref for Address {
    type Target = UserAddress;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl TryInto<H160> for Address {
    type Error = String;

    fn try_into(self) -> Result<H160, Self::Error> {
        match self.hex_address {
            Some(h) => Ok(h),
            None => Err("Not a hex address".into()),
        }
    }
}

impl<'a> Deserialize<'a> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'a> {
        let s: String = Deserialize::deserialize(deserializer)?;

        let inner = cfx_addr_decode(&s).map_err(|e| {
            de::Error::custom(format!("Invalid base32 address: {}", e))
        })?;

        Ok(Address(inner))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let addr_str = cfx_addr_encode(&self.0.body[..], self.0.network)
            .map_err(|e| {
                ser::Error::custom(format!("Failed to encode address: {}", e))
            })?;

        serializer.serialize_str(&addr_str)
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use cfx_addr::Network;
    use serde_json;
    use std::convert::TryInto;

    fn check_deserialize(raw: &str, hex: &str, network: Network) {
        let addr_hex = hex.trim_start_matches("0x").parse().unwrap();
        let parsed: Address = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.network, network);
        assert_eq!(parsed.hex_address, Some(addr_hex));
        assert_eq!(parsed.try_into(), Ok(addr_hex));
    }

    #[test]
    fn test_deserialize_address() {
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
    fn test_deserialize_incorrect_network_prefix() {
        check_deserialize(
            "\"cfy:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_no_network_prefix() {
        check_deserialize(
            "\"022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_incorrect_type() {
        check_deserialize(
            "\"cfx:type.user:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc6\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_incorrect_checksum() {
        check_deserialize(
            "\"cfx:022xg0j5vg1fba4nh7gz372we6740puptmj8nwjfc7\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }
}
