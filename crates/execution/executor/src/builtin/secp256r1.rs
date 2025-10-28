use super::{Error, Precompile};
use cfx_bytes::BytesRef;
use cfx_types::H256;
pub use revm_precompile::secp256r1::{
    verify_impl, P256VERIFY_ADDRESS, P256VERIFY_BASE_GAS_FEE_OSAKA,
};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Secp256R1;

impl Precompile for Secp256R1 {
    fn execute(
        &self, input: &[u8], output: &mut BytesRef,
    ) -> Result<(), Error> {
        let result = if verify_impl(input) {
            H256::from_low_u64_be(1).as_bytes().to_vec()
        } else {
            vec![]
        };
        output.write(0, &result);
        Ok(())
    }
}
