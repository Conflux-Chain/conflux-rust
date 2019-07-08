pub trait DeltaDbTrait {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>>;
}

use super::super::impls::errors::*;
