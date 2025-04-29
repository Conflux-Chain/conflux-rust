use cfx_rpc_primitives::Bytes;
use cfx_types::U256;
use serde::Deserialize;
use std::collections::HashMap;

use super::deserializer::deserialize_str_as_u64;

/// Account information
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountInfo {
    pub balance: U256,
    pub code: Bytes,
    #[serde(deserialize_with = "deserialize_str_as_u64")]
    pub nonce: u64,
    pub storage: HashMap<U256, U256>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_account_info() {
        let json = r#"
        {
            "balance": "0x1",
            "code": "0x1234",
            "nonce": "0x2",
            "storage": {
                "0x1": "0x3",
                "0x2": "0x4"
            }
        }
        "#;

        let account_info: AccountInfo = serde_json::from_str(json).unwrap();
        assert_eq!(account_info.balance, U256::from(1));
        assert_eq!(account_info.code, Bytes::from(vec![0x12, 0x34]));
        assert_eq!(account_info.nonce, 2);
        assert_eq!(
            account_info.storage,
            HashMap::from([
                (U256::from(1), U256::from(3)),
                (U256::from(2), U256::from(4))
            ])
        );
    }
}
