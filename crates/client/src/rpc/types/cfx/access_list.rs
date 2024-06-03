use crate::rpc::types::address::RpcAddress;
use cfx_addr::Network;
use cfx_types::H256;
use primitives::{AccessList, AccessListItem};
use std::convert::Into;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CfxAccessListItem {
    pub address: RpcAddress,
    pub storage_keys: Vec<H256>,
}

impl Into<AccessListItem> for CfxAccessListItem {
    fn into(self) -> AccessListItem {
        AccessListItem {
            address: self.address.hex_address,
            storage_keys: self.storage_keys,
        }
    }
}

pub type CfxAccessList = Vec<CfxAccessListItem>;

pub fn to_primitive_access_list(list: CfxAccessList) -> AccessList {
    list.into_iter().map(|item| item.into()).collect()
}

pub fn from_primitive_access_list(
    list: AccessList, network: Network,
) -> CfxAccessList {
    list.into_iter()
        .map(|item| CfxAccessListItem {
            address: RpcAddress::try_from_h160(item.address, network).unwrap(),
            storage_keys: item.storage_keys,
        })
        .collect()
}
