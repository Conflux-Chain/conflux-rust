use cfx_types::{Address, H256, U256};
use serde::Deserialize;

/// Environment variables
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Env {
    pub current_coinbase: Address,
    #[serde(default)]
    pub current_difficulty: U256,
    pub current_gas_limit: U256,
    pub current_number: U256,
    pub current_timestamp: U256,
    pub current_base_fee: Option<U256>,
    pub previous_hash: Option<H256>,

    pub current_random: Option<H256>,
    pub current_beacon_root: Option<H256>,
    pub current_withdrawals_root: Option<H256>,

    pub parent_blob_gas_used: Option<U256>,
    pub parent_excess_blob_gas: Option<U256>,
    pub parent_target_blobs_per_block: Option<U256>,
    pub current_excess_blob_gas: Option<U256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_env() {
        let json = r#"
        {
            "currentCoinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
            "currentGasLimit": "0x016345785d8a0000",
            "currentNumber": "0x01",
            "currentTimestamp": "0x03e8",
            "currentRandom": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "currentDifficulty": "0x00",
            "currentBaseFee": "0x07",
            "currentExcessBlobGas": "0x00"
        }
        "#;

        let env: Env = serde_json::from_str(json).unwrap();
        println!("{:?}", env);
    }
}
