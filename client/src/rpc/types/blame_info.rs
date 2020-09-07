// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlameInfo {
    pub blame: Option<U64>,
    pub deferred_state_root: Option<H256>,
    pub deferred_receipts_root: Option<H256>,
    pub deferred_logs_bloom_hash: Option<H256>,
}

mod tests {
    use super::*;
    #[test]
    fn test_blame_info () {
        let blame_info = BlameInfo{
            blame: None,
            deferred_state_root: None,
            deferred_receipts_root: None,
            deferred_logs_bloom_hash: None
        };
        let info = serde_json::to_string(&blame_info).unwrap();
        assert_eq!(info,"{\"blame\":null,\"deferredStateRoot\":null,\"deferredReceiptsRoot\":null,\"deferredLogsBloomHash\":null}");
        let blame_info1 = BlameInfo{
            blame: None,
            deferred_state_root: Some(H256::zero()),
            deferred_receipts_root: Some(H256::zero()),
            deferred_logs_bloom_hash: Some(H256::zero())
        };
        let info1 = serde_json::to_string(&blame_info1).unwrap();
        assert_eq!(info1,"{\"blame\":null,\"deferredStateRoot\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"deferredReceiptsRoot\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"deferredLogsBloomHash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}");
    }
}