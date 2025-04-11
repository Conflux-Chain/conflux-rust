use crate::Transaction;
use cfx_rpc_cfx_types::TransactionStatus;
use cfx_types::{Address, U256, U64};
use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize, Serialize,
};
use std::{collections::BTreeMap, fmt, str::FromStr};

#[derive(Default, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AccountPendingTransactions {
    pub pending_transactions: Vec<Transaction>,
    pub first_tx_status: Option<TransactionStatus>,
    pub pending_count: U64,
}

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct TxpoolStatus {
    pub pending: U64,
    pub queued: U64,
}

/// Transaction summary as found in the Txpool Inspection property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxpoolInspectSummary {
    /// Recipient (None when contract creation)
    pub to: Option<Address>,
    /// Transferred value
    pub value: U256,
    /// Gas amount
    pub gas: u64,
    /// Gas Price
    pub gas_price: u128,
}

impl TxpoolInspectSummary {
    /// Extracts the [`TxpoolInspectSummary`] from a transaction.
    pub fn from_tx(tx: Transaction) -> Self {
        Self {
            to: tx.to,
            value: tx.value,
            gas: tx.gas.as_u64(),
            gas_price: tx
                .max_fee_per_gas
                .unwrap_or(tx.gas_price.unwrap_or_default())
                .as_u128(),
        }
    }
}

impl From<Transaction> for TxpoolInspectSummary {
    fn from(value: Transaction) -> Self { Self::from_tx(value) }
}

/// Visitor struct for TxpoolInspectSummary.
struct TxpoolInspectSummaryVisitor;

/// Walk through the deserializer to parse a txpool inspection summary into the
/// `TxpoolInspectSummary` struct.
impl Visitor<'_> for TxpoolInspectSummaryVisitor {
    type Value = TxpoolInspectSummary;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("to: value wei + gasLimit gas × gas_price wei")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where E: de::Error {
        let addr_split: Vec<&str> = value.split(": ").collect();
        if addr_split.len() != 2 {
            return Err(de::Error::custom(
                "invalid format for TxpoolInspectSummary: to",
            ));
        }
        let value_split: Vec<&str> = addr_split[1].split(" wei + ").collect();
        if value_split.len() != 2 {
            return Err(de::Error::custom(
                "invalid format for TxpoolInspectSummary: gasLimit",
            ));
        }
        let gas_split: Vec<&str> = value_split[1].split(" gas × ").collect();
        if gas_split.len() != 2 {
            return Err(de::Error::custom(
                "invalid format for TxpoolInspectSummary: gas",
            ));
        }
        let gas_price_split: Vec<&str> = gas_split[1].split(" wei").collect();
        if gas_price_split.len() != 2 {
            return Err(de::Error::custom(
                "invalid format for TxpoolInspectSummary: gas_price",
            ));
        }
        let to = match addr_split[0] {
            "" | "0x" | "contract creation" => None,
            addr => Some(
                Address::from_str(addr.trim_start_matches("0x"))
                    .map_err(de::Error::custom)?,
            ),
        };
        let value =
            U256::from_dec_str(value_split[0]).map_err(de::Error::custom)?;
        let gas = u64::from_str(gas_split[0]).map_err(de::Error::custom)?;
        let gas_price =
            u128::from_str(gas_price_split[0]).map_err(de::Error::custom)?;

        Ok(TxpoolInspectSummary {
            to,
            value,
            gas,
            gas_price,
        })
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where E: de::Error {
        self.visit_str(&value)
    }
}

/// Implement the `Deserialize` trait for `TxpoolInspectSummary` struct.
impl<'de> Deserialize<'de> for TxpoolInspectSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        deserializer.deserialize_str(TxpoolInspectSummaryVisitor)
    }
}

/// Implement the `Serialize` trait for `TxpoolInspectSummary` struct so that
/// the format matches the one from geth.
impl Serialize for TxpoolInspectSummary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let formatted_to = self.to.map_or_else(
            || "contract creation".to_string(),
            |to| format!("{to:?}"),
        );
        let formatted = format!(
            "{}: {} wei + {} gas × {} wei",
            formatted_to, self.value, self.gas, self.gas_price
        );
        serializer.serialize_str(&formatted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxpoolContent<T = Transaction> {
    /// pending tx
    pub pending: BTreeMap<Address, BTreeMap<String, T>>,
    /// queued tx
    pub queued: BTreeMap<Address, BTreeMap<String, T>>,
}

impl<T> Default for TxpoolContent<T> {
    fn default() -> Self {
        Self {
            pending: BTreeMap::new(),
            queued: BTreeMap::new(),
        }
    }
}

impl<T> TxpoolContent<T> {
    /// Removes the transactions from the given sender
    pub fn remove_from(&mut self, sender: &Address) -> TxpoolContentFrom<T> {
        TxpoolContentFrom {
            pending: self.pending.remove(sender).unwrap_or_default(),
            queued: self.queued.remove(sender).unwrap_or_default(),
        }
    }

    /// Returns an iterator over references to all pending transactions
    pub fn pending_transactions(&self) -> impl Iterator<Item = &T> {
        self.pending
            .values()
            .flat_map(|nonce_map| nonce_map.values())
    }

    /// Returns an iterator over references to all queued transactions
    pub fn queued_transactions(&self) -> impl Iterator<Item = &T> {
        self.queued
            .values()
            .flat_map(|nonce_map| nonce_map.values())
    }

    /// Returns an iterator over references to all pending transactions from a
    /// specific sender
    pub fn pending_transactions_from(
        &self, sender: &Address,
    ) -> impl Iterator<Item = &T> {
        self.pending
            .get(sender)
            .into_iter()
            .flat_map(|nonce_map| nonce_map.values())
    }

    /// Returns an iterator over references to all queued transactions from a
    /// specific sender
    pub fn queued_transactions_from(
        &self, sender: &Address,
    ) -> impl Iterator<Item = &T> {
        self.queued
            .get(sender)
            .into_iter()
            .flat_map(|nonce_map| nonce_map.values())
    }
}

impl<T> TxpoolContent<T> {
    /// Returns an iterator that consumes and yields all pending transactions
    pub fn into_pending_transactions(self) -> impl Iterator<Item = T> {
        self.pending
            .into_values()
            .flat_map(|nonce_map| nonce_map.into_values())
    }

    /// Returns an iterator that consumes and yields all queued transactions
    pub fn into_queued_transactions(self) -> impl Iterator<Item = T> {
        self.queued
            .into_values()
            .flat_map(|nonce_map| nonce_map.into_values())
    }

    /// Returns an iterator that consumes and yields all pending transactions
    /// from a specific sender
    pub fn into_pending_transactions_from(
        mut self, sender: &Address,
    ) -> impl Iterator<Item = T> {
        self.pending
            .remove(sender)
            .into_iter()
            .flat_map(|nonce_map| nonce_map.into_values())
    }

    /// Returns an iterator that consumes and yields all queued transactions
    /// from a specific sender
    pub fn into_queued_transactions_from(
        mut self, sender: &Address,
    ) -> impl Iterator<Item = T> {
        self.queued
            .remove(sender)
            .into_iter()
            .flat_map(|nonce_map| nonce_map.into_values())
    }
}

/// Transaction Pool Content From
///
/// Same as [TxpoolContent] but for a specific address.
///
/// See [here](https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_contentFrom) for more details
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxpoolContentFrom<T = Transaction> {
    /// pending tx
    pub pending: BTreeMap<String, T>,
    /// queued tx
    pub queued: BTreeMap<String, T>,
}

impl<T> Default for TxpoolContentFrom<T> {
    fn default() -> Self {
        Self {
            pending: BTreeMap::new(),
            queued: BTreeMap::new(),
        }
    }
}

/// Transaction Pool Inspect
///
/// The inspect inspection property can be queried to list a textual summary
/// of all the transactions currently pending for inclusion in the next
/// block(s), as well as the ones that are being scheduled for future execution
/// only. This is a method specifically tailored to developers to quickly see
/// the transactions in the pool and find any potential issues.
///
/// See [here](https://geth.ethereum.org/docs/rpc/ns-txpool#txpool_inspect) for more details
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxpoolInspect {
    /// pending tx
    pub pending: BTreeMap<Address, BTreeMap<String, TxpoolInspectSummary>>,
    /// queued tx
    pub queued: BTreeMap<Address, BTreeMap<String, TxpoolInspectSummary>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use similar_asserts::assert_eq;

    #[test]
    fn serde_txpool_inspect() {
        let txpool_inspect_json = r#"
{
  "pending": {
    "0x0512261a7486b1e29704ac49a5eb355b6fd86872": {
      "124930": "0x000000000000000000000000000000000000007E: 0 wei + 100187 gas × 20000000000 wei"
    },
    "0x201354729f8d0f8b64e9a0c353c672c6a66b3857": {
      "252350": "0xd10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF: 0 wei + 65792 gas × 2000000000 wei",
      "252351": "0xd10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF: 0 wei + 65792 gas × 2000000000 wei",
      "252352": "0xd10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF: 0 wei + 65780 gas × 2000000000 wei",
      "252353": "0xd10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF: 0 wei + 65780 gas × 2000000000 wei"
    },
    "0x00000000863B56a3C1f0F1be8BC4F8b7BD78F57a": {
      "40": "contract creation: 0 wei + 612412 gas × 6000000000 wei"
    }
  },
  "queued": {
    "0x0f87ffcd71859233eb259f42b236c8e9873444e3": {
      "7": "0x3479BE69e07E838D9738a301Bb0c89e8EA2Bef4a: 1000000000000000 wei + 21000 gas × 10000000000 wei",
      "8": "0x73Aaf691bc33fe38f86260338EF88f9897eCaa4F: 1000000000000000 wei + 21000 gas × 10000000000 wei"
    },
    "0x307e8f249bcccfa5b245449256c5d7e6e079943e": {
      "3": "0x73Aaf691bc33fe38f86260338EF88f9897eCaa4F: 10000000000000000 wei + 21000 gas × 10000000000 wei"
    }
  }
}"#;
        let deserialized: TxpoolInspect =
            serde_json::from_str(txpool_inspect_json).unwrap();
        assert_eq!(deserialized, expected_txpool_inspect());

        let serialized = serde_json::to_string(&deserialized).unwrap();
        let deserialized2: TxpoolInspect =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized2, deserialized);
    }

    #[test]
    fn serde_txpool_status() {
        let txpool_status_json = r#"
{
  "pending": "0x23",
  "queued": "0x20"
}"#;
        let deserialized: TxpoolStatus =
            serde_json::from_str(txpool_status_json).unwrap();
        let serialized: String =
            serde_json::to_string_pretty(&deserialized).unwrap();
        assert_eq!(txpool_status_json.trim(), serialized);
    }

    fn expected_txpool_inspect() -> TxpoolInspect {
        let mut pending_map = BTreeMap::new();
        let mut pending_map_inner = BTreeMap::new();
        pending_map_inner.insert(
            "124930".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "000000000000000000000000000000000000007E",
                    )
                    .unwrap(),
                ),
                value: U256::from(0u128),
                gas: 100187,
                gas_price: 20000000000u128,
            },
        );
        pending_map.insert(
            Address::from_str("0512261a7486b1e29704ac49a5eb355b6fd86872")
                .unwrap(),
            pending_map_inner.clone(),
        );
        pending_map_inner.clear();
        pending_map_inner.insert(
            "252350".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "d10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF",
                    )
                    .unwrap(),
                ),
                value: U256::from(0u128),
                gas: 65792,
                gas_price: 2000000000u128,
            },
        );
        pending_map_inner.insert(
            "252351".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "d10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF",
                    )
                    .unwrap(),
                ),
                value: U256::from(0u128),
                gas: 65792,
                gas_price: 2000000000u128,
            },
        );
        pending_map_inner.insert(
            "252352".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "d10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF",
                    )
                    .unwrap(),
                ),
                value: U256::from(0u128),
                gas: 65780,
                gas_price: 2000000000u128,
            },
        );
        pending_map_inner.insert(
            "252353".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "d10e3Be2bc8f959Bc8C41CF65F60dE721cF89ADF",
                    )
                    .unwrap(),
                ),
                value: U256::from(0u128),
                gas: 65780,
                gas_price: 2000000000u128,
            },
        );
        pending_map.insert(
            Address::from_str("201354729f8d0f8b64e9a0c353c672c6a66b3857")
                .unwrap(),
            pending_map_inner.clone(),
        );
        pending_map_inner.clear();
        pending_map_inner.insert(
            "40".to_string(),
            TxpoolInspectSummary {
                to: None,
                value: U256::from(0u128),
                gas: 612412,
                gas_price: 6000000000u128,
            },
        );
        pending_map.insert(
            Address::from_str("00000000863B56a3C1f0F1be8BC4F8b7BD78F57a")
                .unwrap(),
            pending_map_inner,
        );
        let mut queued_map = BTreeMap::new();
        let mut queued_map_inner = BTreeMap::new();
        queued_map_inner.insert(
            "7".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "3479BE69e07E838D9738a301Bb0c89e8EA2Bef4a",
                    )
                    .unwrap(),
                ),
                value: U256::from(1000000000000000u128),
                gas: 21000,
                gas_price: 10000000000u128,
            },
        );
        queued_map_inner.insert(
            "8".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "73Aaf691bc33fe38f86260338EF88f9897eCaa4F",
                    )
                    .unwrap(),
                ),
                value: U256::from(1000000000000000u128),
                gas: 21000,
                gas_price: 10000000000u128,
            },
        );
        queued_map.insert(
            Address::from_str("0f87ffcd71859233eb259f42b236c8e9873444e3")
                .unwrap(),
            queued_map_inner.clone(),
        );
        queued_map_inner.clear();
        queued_map_inner.insert(
            "3".to_string(),
            TxpoolInspectSummary {
                to: Some(
                    Address::from_str(
                        "73Aaf691bc33fe38f86260338EF88f9897eCaa4F",
                    )
                    .unwrap(),
                ),
                value: U256::from(10000000000000000u128),
                gas: 21000,
                gas_price: 10000000000u128,
            },
        );
        queued_map.insert(
            Address::from_str("307e8f249bcccfa5b245449256c5d7e6e079943e")
                .unwrap(),
            queued_map_inner,
        );

        TxpoolInspect {
            pending: pending_map,
            queued: queued_map,
        }
    }
}
