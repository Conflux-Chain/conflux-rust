use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

use super::{AccountInfo, Env, SpecName, Test, TransactionParts};
use cfx_bytes::Bytes;
use cfx_types::Address;

/// Single test unit struct
#[derive(Debug, PartialEq, Eq, Deserialize)]
//#[serde(deny_unknown_fields)]
// field config
pub struct TestUnit {
    /// Test info is optional.
    #[serde(default, rename = "_info")]
    pub info: Option<serde_json::Value>,

    pub env: Env,
    pub pre: HashMap<Address, AccountInfo>,
    pub post: BTreeMap<SpecName, Vec<Test>>,
    pub transaction: TransactionParts,
    #[serde(default)]
    pub out: Option<Bytes>,
    //pub config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_test_unit() {
        let json = r#"
        {
            "env": {
                "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "currentGasLimit": "0x016345785d8a0000",
                "currentNumber": "0x01",
                "currentTimestamp": "0x03e8",
                "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "currentDifficulty": "0x00",
                "currentBaseFee": "0x07",
                "currentExcessBlobGas": "0x0e0000"
            },
            "pre": {
                "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
                    "nonce": "0x00",
                    "balance": "0x04b2e7dc",
                    "code": "0x",
                    "storage": {}
                }
            },
            "transaction": {
                "nonce": "0x00",
                "maxPriorityFeePerGas": "0x00",
                "maxFeePerGas": "0x07",
                "gasLimit": [
                    "0x6a44"
                ],
                "to": "0x8a0a19589531694250d570040a0c4b74576919b8",
                "value": [
                    "0x00"
                ],
                "data": [
                    "0x00"
                ],
                "accessLists": [
                    [
                        {
                            "address": "0x0000000000000000000000000000000000000064",
                            "storageKeys": [
                                "0x0000000000000000000000000000000000000000000000000000000000000064",
                                "0x00000000000000000000000000000000000000000000000000000000000000c8"
                            ]
                        }
                    ]
                ],
                "maxFeePerBlobGas": "0x64",
                "blobVersionedHashes": [
                    "0x0100000000000000000000000000000000000000000000000000000000000000",
                    "0x0100000000000000000000000000000000000000000000000000000000000001",
                    "0x0100000000000000000000000000000000000000000000000000000000000002",
                    "0x0100000000000000000000000000000000000000000000000000000000000003",
                    "0x0100000000000000000000000000000000000000000000000000000000000004",
                    "0x0100000000000000000000000000000000000000000000000000000000000005"
                ],
                "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
                "secretKey": "0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
            },
            "post": {
                "Cancun": [
                    {
                        "hash": "0x70151ef6e11989505a79932f38c191bdbb22a2ff455460ddc53ef3b056d378ff",
                        "logs": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                        "txbytes": "0x03f9018701808007826a44948a0a19589531694250d570040a0c4b74576919b88000f85bf859940000000000000000000000000000000000000064f842a00000000000000000000000000000000000000000000000000000000000000064a000000000000000000000000000000000000000000000000000000000000000c864f8c6a00100000000000000000000000000000000000000000000000000000000000000a00100000000000000000000000000000000000000000000000000000000000001a00100000000000000000000000000000000000000000000000000000000000002a00100000000000000000000000000000000000000000000000000000000000003a00100000000000000000000000000000000000000000000000000000000000004a0010000000000000000000000000000000000000000000000000000000000000501a01fd714a1b7065e945bffbe064dfe72b1f0a9f482cd3d03ffa78884bd9331b19ea04066aba133e51239e007914fc7ee21bd2591c39d1d201b3b813f03d2f4ca9088",
                        "indexes": {
                            "data": 0,
                            "gas": 0,
                            "value": 0
                        },
                        "state": {
                            "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
                                "nonce": "0x01",
                                "balance": "0x04a40000",
                                "code": "0x",
                                "storage": {}
                            }
                        }
                    }
                ]
            },
            "config": {
                "blobSchedule": {
                    "Cancun": {
                        "target": "0x03",
                        "max": "0x06",
                        "baseFeeUpdateFraction": "0x32f0ed"
                    }
                },
                "chainid": "0x01"
            },
            "_info": {
                "hash": "0xd992bae1a97e5e6134325c6b02b86087700fef37fa53a6f5a72c50829d8fca77",
                "comment": "`execution-spec-tests` generated test",
                "filling-transition-tool": "ethereum-spec-evm-resolver 0.0.5",
                "description": "Test function documentation:\n\n    Check that transaction is accepted when user can exactly afford the blob gas specified (and\n    max_fee_per_gas would be enough for current block).\n\n    - Transactions with max fee equal or higher than current block base fee\n    - Transactions with and without priority fee\n    - Transactions with and without value\n    - Transactions with and without calldata\n    - Transactions with max fee per blob gas lower or higher than the priority fee",
                "url": "https://github.com/ethereum/execution-spec-tests/tree/v4.1.0/tests/cancun/eip4844_blobs/test_blob_txs.py#L633",
                "fixture-format": "state_test",
                "reference-spec": "https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md",
                "reference-spec-version": "de2e4a46ad93fc04e6fe3174dc6e90a3307bdb5f",
                "eels-resolution": {
                    "git-url": "https://github.com/ethereum/execution-specs.git",
                    "branch": "master",
                    "commit": "78fb726158c69d8fa164e28f195fabf6ab59b915"
                }
            }
        }
        "#;
        let test_unit: TestUnit = serde_json::from_str(json).unwrap();
        println!("{:?}", test_unit);
    }
}
