// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_addr::{cfx_addr_decode, cfx_addr_encode, EncodingOptions, Network};
use cfx_types::H160;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// This is the address type used in Rpc. It deserializes user's Rpc input, or
/// it prepares the base32 address for Rpc output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RpcAddress {
    /// It's user's input or encoded output address.
    pub base32_address: String,
    pub hex_address: H160,
    pub network: Network,
}

impl RpcAddress {
    pub fn try_from_h160(
        hex_address: H160, network: Network,
    ) -> Result<Self, String> {
        let base32_address =
            cfx_addr_encode(&hex_address.0, network, EncodingOptions::QrCode)
                .map_err(|e| e.to_string())?;
        Ok(Self {
            base32_address,
            hex_address,
            network,
        })
    }

    pub fn null(network: Network) -> Result<Self, String> {
        Self::try_from_h160(H160::default(), network)
    }
}

impl From<RpcAddress> for H160 {
    fn from(x: RpcAddress) -> Self { x.hex_address }
}

impl<'a> Deserialize<'a> for RpcAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'a> {
        let s: String = Deserialize::deserialize(deserializer)?;

        let parsed_address = cfx_addr_decode(&s).map_err(|e| {
            de::Error::custom(format!(
                "Invalid base32 address: input {} error {}",
                s, e
            ))
        })?;
        match parsed_address.hex_address {
            None => Err(de::Error::custom(format!(
                "Invalid base32 address: input {} not a SIZE_160 address.",
                s
            ))),
            Some(hex_address) => Ok(Self {
                base32_address: parsed_address.input_base32_address,
                hex_address,
                network: parsed_address.network,
            }),
        }
    }
}

impl Serialize for RpcAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&self.base32_address)
    }
}

#[derive(Debug)]
pub struct RcpAddressNetworkInconsistent {
    pub from_network: Network,
    pub to_network: Network,
}

impl fmt::Display for RcpAddressNetworkInconsistent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "network prefix inconsistent in from({}) and to({})",
            self.from_network, self.to_network
        )
    }
}

pub fn check_rpc_address_network(
    rpc_request_network: Option<Network>, expected: &Network,
) -> Result<(), UnexpectedRpcAddressNetwork> {
    if let Some(rpc_network) = rpc_request_network {
        if rpc_network != *expected {
            return Err(UnexpectedRpcAddressNetwork {
                expected: *expected,
                got: rpc_network,
            });
        }
    }
    Ok(())
}

pub fn check_two_rpc_address_network_match(
    from: Option<&RpcAddress>, to: Option<&RpcAddress>,
) -> Result<Option<Network>, RcpAddressNetworkInconsistent> {
    match (from, to) {
        (None, None) => Ok(None),
        (None, Some(b)) => Ok(Some(b.network)),
        (Some(a), None) => Ok(Some(a.network)),
        (Some(a), Some(b)) => {
            if a.network != b.network {
                return Err(RcpAddressNetworkInconsistent {
                    from_network: a.network,
                    to_network: b.network,
                });
            }
            Ok(Some(a.network))
        }
    }
}

#[derive(Debug)]
pub struct UnexpectedRpcAddressNetwork {
    pub expected: Network,
    pub got: Network,
}

impl fmt::Display for UnexpectedRpcAddressNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "network prefix unexpected: ours {}, got {}",
            self.expected, self.got
        )
    }
}
#[cfg(test)]
mod tests {
    use super::RpcAddress;
    use cfx_addr::{cfx_addr_encode, EncodingOptions, Network};
    use cfx_types::H160;
    use log::debug;
    use serde_json;

    fn check_deserialize(base32_address: &str, hex: &str, network: Network) {
        let addr_hex: H160 = hex.trim_start_matches("0x").parse().unwrap();
        let parsed_result = serde_json::from_str::<RpcAddress>(base32_address);
        debug!(
            "parsed: {:?}, expected hex addr {:?}, expected base32 addr {:?}",
            parsed_result,
            addr_hex,
            cfx_addr_encode(
                addr_hex.as_bytes(),
                network,
                EncodingOptions::Simple
            )
        );
        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.network, network);
        assert_eq!(parsed.hex_address, addr_hex);
    }

    #[test]
    fn test_deserialize_address() {
        check_deserialize(
            "\"cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );

        check_deserialize(
            "\"cfxtest:acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Test,
        );

        check_deserialize(
            "\"cfxtest:type.contract:acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Test,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_incorrect_network_prefix() {
        check_deserialize(
            "\"cfy:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_no_network_prefix() {
        check_deserialize(
            "\"acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_incorrect_type() {
        check_deserialize(
            "\"cfx:type.user:acc7uawf5ubtnmezvhu9dhc6sghea0403y2dgpyfjp\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }

    #[test]
    #[should_panic]
    fn test_deserialize_incorrect_checksum() {
        check_deserialize(
            "\"cfx:acc7uawf5ubtnmezvhu9dhc6sghea0403ywjz6wtpg\"",
            "0x85d80245dc02f5a89589e1f19c5c718e405b56cd",
            Network::Main,
        );
    }
}
