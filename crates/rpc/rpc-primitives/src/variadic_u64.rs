use serde::{Deserialize, Deserializer};
use serde_utils::num::deserialize_u64_from_num_or_hex;
use std::fmt;

// support both hex strings and number deserialization
#[derive(Debug)]
pub struct U64(u64);

impl fmt::Display for U64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for U64 {
    fn from(value: u64) -> Self { U64(value) }
}

impl U64 {
    pub fn as_u64(&self) -> u64 { self.0 }
}

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        Ok(U64(deserialize_u64_from_num_or_hex(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_u64_or_hex() {
        let json_data = r#""0x1a""#;
        let my_struct: U64 = serde_json::from_str(json_data).unwrap();
        assert_eq!(my_struct.as_u64(), 26);

        let json_data = r#"26"#;
        let my_struct: U64 = serde_json::from_str(json_data).unwrap();
        assert_eq!(my_struct.as_u64(), 26);
    }
}
