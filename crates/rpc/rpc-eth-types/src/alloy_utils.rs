use alloy_primitives::{map::B256Map, TxKind, B256};
use alloy_primitives_wrapper::{WAddress, WB256};
use alloy_rpc_types_eth::transaction::{
    AccessList as EthAccessList, AccessListItem as EthAccessListItem,
};
use cfx_types::{Address, H256};
use primitives::{AccessList, AccessListItem};
use std::collections::HashMap;

// converts that convert alloy rpc eth types to our internal types

pub fn convert_access_list_item(item: EthAccessListItem) -> AccessListItem {
    AccessListItem {
        address: WAddress::from(item.address).into(),
        storage_keys: item
            .storage_keys
            .into_iter()
            .map(|key| WB256::from(key).into())
            .collect(),
    }
}

pub fn convert_access_list(list: EthAccessList) -> AccessList {
    list.0.into_iter().map(convert_access_list_item).collect()
}

pub fn convert_option_tx_kind(tx_kind: Option<TxKind>) -> Option<Address> {
    match tx_kind {
        Some(addr) => match addr {
            TxKind::Create => None,
            TxKind::Call(to) => Some(WAddress::from(to).into()),
        },
        None => None,
    }
}

pub fn convert_state(state: B256Map<B256>) -> HashMap<H256, H256> {
    state
        .into_iter()
        .map(|(k, v)| (WB256::from(k).into(), WB256::from(v).into()))
        .collect()
}
