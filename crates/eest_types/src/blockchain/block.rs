use super::Transaction;
use cfx_rpc_primitives::Bytes;
use cfx_types::{Address, Bloom, H256, U256, U64};
use serde::Deserialize;

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    pub parent_hash: H256,
    pub uncle_hash: H256,
    pub coinbase: Address,
    pub state_root: H256,
    pub transactions_trie: H256,
    pub receipt_trie: H256,
    pub bloom: Bloom,
    pub difficulty: U256,
    pub number: U256,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: U256,
    pub extra_data: Bytes,
    pub mix_hash: H256,
    pub nonce: U64, // Bytes of a 8-byte fixed length.
    pub base_fee_per_gas: Option<U256>,
    pub withdrawals_root: Option<H256>,
    pub blob_gas_used: Option<U256>,
    pub excess_blob_gas: Option<U256>,
    pub parent_beacon_block_root: Option<H256>,
    pub requests_hash: Option<H256>,
    pub hash: H256,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub block_header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub uncle_headers: Vec<BlockHeader>,
    pub withdrawals: Option<Vec<Withdrawal>>,
    pub rlp: Bytes,
    pub blocknumber: Option<String>, // TODO deserialize to u64
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    index: U256,
    validator_index: U256,
    address: Address,
    amount: U256,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidBlock {
    pub rlp: Bytes,
    pub expect_exception: String,
    pub rlp_decoded: Option<Block>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_withdrawal() {
        let json_str = r#"{
            "index": "0x00",
            "validatorIndex": "0x00",
            "address": "0x0000000000000000000000000000000000000002",
            "amount": "0x01"
        }"#;

        let data: Withdrawal = serde_json::from_str(json_str).unwrap();
        assert_eq!(data.amount, U256::from(1));
    }

    #[test]
    fn recover_block_header() {
        let json_str = r#"{
            "parentHash": "0x75f987ffc84f12861a575922ee8620845a804f7c79f2dfeef0ca352d0fe1c46a",
            "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "coinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "stateRoot": "0xc2a77e1e008094eb69970a5ca782d3db246a13f27d8eb9f9dbda741f594c4f32",
            "transactionsTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "receiptTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "difficulty": "0x00",
            "number": "0x01",
            "gasLimit": "0x016345785d8a0000",
            "gasUsed": "0x00",
            "timestamp": "0x0c",
            "extraData": "0x",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000000",
            "baseFeePerGas": "0x07",
            "withdrawalsRoot": "0xe69c7b5847f8c1bb8052999046c12ba942ad4d05e5627b0d339ec7772574e544",
            "blobGasUsed": "0x00",
            "excessBlobGas": "0x00",
            "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "hash": "0xe6f643b08c3757450d93d5bfa27168a2af5a861ac3bd2793ca57650f9d77a50c"
        }"#;

        let data: BlockHeader = serde_json::from_str(json_str).unwrap();
        assert_eq!(data.number, U256::from(1));
    }

    #[test]
    fn recover_block_basic() {
        let json_str = r#"{
            "blockHeader": {
                "parentHash": "0x75f987ffc84f12861a575922ee8620845a804f7c79f2dfeef0ca352d0fe1c46a",
                "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                "coinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                "stateRoot": "0xc2a77e1e008094eb69970a5ca782d3db246a13f27d8eb9f9dbda741f594c4f32",
                "transactionsTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                "receiptTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                "bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "difficulty": "0x00",
                "number": "0x01",
                "gasLimit": "0x016345785d8a0000",
                "gasUsed": "0x00",
                "timestamp": "0x0c",
                "extraData": "0x",
                "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "nonce": "0x0000000000000000",
                "baseFeePerGas": "0x07",
                "withdrawalsRoot": "0xe69c7b5847f8c1bb8052999046c12ba942ad4d05e5627b0d339ec7772574e544",
                "blobGasUsed": "0x00",
                "excessBlobGas": "0x00",
                "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "hash": "0xe6f643b08c3757450d93d5bfa27168a2af5a861ac3bd2793ca57650f9d77a50c"
            },
            "transactions": [
                {
                    "type": "0x00",
                    "chainId": "0x01",
                    "nonce": "0x00",
                    "gasPrice": "0x0a",
                    "gasLimit": "0x07a120",
                    "to": "0x0000000000000000000000000000000000001000",
                    "value": "0x00",
                    "data": "0x00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002003fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2efffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                    "v": "0x26",
                    "r": "0xb71d8dd5ac327ec1b822930c066a9d0931a26f8529cbd0dca51a6a1f3fc508c9",
                    "s": "0x63698823fb964779539d8fd4d016e7326cbd9dab987233458980d422776167b5",
                    "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
                }
            ],
            "uncleHeaders": [],
            "withdrawals": [
                {
                    "index": "0x00",
                    "validatorIndex": "0x00",
                    "address": "0x0000000000000000000000000000000000000002",
                    "amount": "0x01"
                }
            ],
            "rlp": "0xf90259f9023aa075f987ffc84f12861a575922ee8620845a804f7c79f2dfeef0ca352d0fe1c46aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0c2a77e1e008094eb69970a5ca782d3db246a13f27d8eb9f9dbda741f594c4f32a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800188016345785d8a0000800c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a0e69c7b5847f8c1bb8052999046c12ba942ad4d05e5627b0d339ec7772574e5448080a00000000000000000000000000000000000000000000000000000000000000000c0c0d9d8808094000000000000000000000000000000000000000201",
            "blocknumber": "1"
        }"#;

        let data: Block = serde_json::from_str(json_str).unwrap();
        assert_eq!(data.blocknumber.is_some(), true);
        assert_eq!(data.blocknumber.unwrap().parse(), Ok(1));
    }

    #[test]
    fn recover_invalid_block() {
        let json_str = r#"{
            "rlp": "0xf9035ef90242a0d9afd2e454bd4dbaba688c0f8a0463689e50da4fe4bd675a9fb59434bedc2d55a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa00db85f0bc22f84493da39f9c08113aea13559eb14f9cac67e5db5007d01c5df4a01cbe160c60be9946c1477734baf89a03a0d6d75b8d64b3bed9d3954a1976c656a0eaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12abb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800188016345785d8a00008252080c80a0000000000000000000000000000000000000000000000000000000000000000088000000000000000007a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42183040000830e0000a00000000000000000000000000000000000000000000000000000000000000000f90114b88803f88501808007825208948a0a19589531694250d570040a0c4b74576919b80180c001e1a0010000000000000000000000000000000000000000000000000000000000000001a06c120e55aeb31122c5caad29e69d28ec90abb71e089e0cdf4aebbf51bbc46a89a067983552dabf029ffb7ac58209a620d4a98eeeaf3df55bc9eb8e7684051ac70ab88803f88501018007825208948a0a19589531694250d570040a0c4b74576919b80180c001e1a0010000000000000000000000000000000000000000000000000000000000000080a04fc1b52cdbb48421d17e7ccfc33496c95bae6ecfd8f29816699f151d92e4ed9ca074271236ba3a66db6ea60f4482287b8f52de28a6a525626c55e741c54296309bc0c0",
            "expectException": "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS",
            "rlp_decoded": {
                "blockHeader": {
                    "parentHash": "0xd9afd2e454bd4dbaba688c0f8a0463689e50da4fe4bd675a9fb59434bedc2d55",
                    "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "coinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
                    "stateRoot": "0x0db85f0bc22f84493da39f9c08113aea13559eb14f9cac67e5db5007d01c5df4",
                    "transactionsTrie": "0x1cbe160c60be9946c1477734baf89a03a0d6d75b8d64b3bed9d3954a1976c656",
                    "receiptTrie": "0xeaa8c40899a61ae59615cf9985f5e2194f8fd2b57d273be63bde6733e89b12ab",
                    "bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "difficulty": "0x00",
                    "number": "0x01",
                    "gasLimit": "0x016345785d8a0000",
                    "gasUsed": "0x5208",
                    "timestamp": "0x0c",
                    "extraData": "0x",
                    "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "nonce": "0x0000000000000000",
                    "baseFeePerGas": "0x07",
                    "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                    "blobGasUsed": "0x040000",
                    "excessBlobGas": "0x0e0000",
                    "parentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "hash": "0x4ff059d45cd9c3aaee26292786a7ea8bf6d00ec330bd50e00d2a6b1c9b6ed06e"
                },
                "transactions": [
                    {
                        "type": "0x03",
                        "chainId": "0x01",
                        "nonce": "0x00",
                        "maxPriorityFeePerGas": "0x00",
                        "maxFeePerGas": "0x07",
                        "gasLimit": "0x5208",
                        "to": "0x8a0a19589531694250d570040a0c4b74576919b8",
                        "value": "0x01",
                        "data": "0x",
                        "accessList": [],
                        "maxFeePerBlobGas": "0x01",
                        "blobVersionedHashes": [
                            "0x0100000000000000000000000000000000000000000000000000000000000000"
                        ],
                        "v": "0x01",
                        "r": "0x6c120e55aeb31122c5caad29e69d28ec90abb71e089e0cdf4aebbf51bbc46a89",
                        "s": "0x67983552dabf029ffb7ac58209a620d4a98eeeaf3df55bc9eb8e7684051ac70a",
                        "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
                    },
                    {
                        "type": "0x03",
                        "chainId": "0x01",
                        "nonce": "0x01",
                        "maxPriorityFeePerGas": "0x00",
                        "maxFeePerGas": "0x07",
                        "gasLimit": "0x5208",
                        "to": "0x8a0a19589531694250d570040a0c4b74576919b8",
                        "value": "0x01",
                        "data": "0x",
                        "accessList": [],
                        "maxFeePerBlobGas": "0x01",
                        "blobVersionedHashes": [
                            "0x0100000000000000000000000000000000000000000000000000000000000000"
                        ],
                        "v": "0x00",
                        "r": "0x4fc1b52cdbb48421d17e7ccfc33496c95bae6ecfd8f29816699f151d92e4ed9c",
                        "s": "0x74271236ba3a66db6ea60f4482287b8f52de28a6a525626c55e741c54296309b",
                        "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"
                    }
                ],
                "uncleHeaders": [],
                "withdrawals": [],
                "blocknumber": "1"
            }
        }"#;

        let data: InvalidBlock = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            data.expect_exception,
            "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS"
        );
    }
}
