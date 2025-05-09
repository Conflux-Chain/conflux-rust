use cfx_types::H64;
use std::str;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SubId(H64);

impl str::FromStr for SubId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("0x") {
            Ok(SubId(s[2..].parse().map_err(|e| format!("{}", e))?))
        } else {
            Err("The id must start with 0x".into())
        }
    }
}
impl SubId {
    pub fn new(data: H64) -> Self { SubId(data) }

    // TODO: replace `format!` see [#10412](https://github.com/paritytech/parity-ethereum/issues/10412)
    pub fn as_string(&self) -> String { format!("{:?}", self.0) }
}

pub mod random {
    use rand;

    pub type Rng = rand::rngs::OsRng;

    pub fn new() -> Rng { rand::rngs::OsRng }
}
