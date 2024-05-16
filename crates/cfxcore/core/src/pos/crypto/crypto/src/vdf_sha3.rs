use crate::{HashValue, VerifiableDelayFunction};

/// VDF SHA256.
pub struct VdfSha3 {}

impl VerifiableDelayFunction for VdfSha3 {
    fn solve(
        &self, challenge: &[u8], difficulty: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut output = HashValue::sha3_256_of(challenge);
        for _ in 0..difficulty {
            output = HashValue::sha3_256_of(output.as_ref());
        }
        Ok(output.to_vec())
    }

    fn verify(
        &self, challenge: &[u8], difficulty: u64, alleged_solution: &[u8],
    ) -> anyhow::Result<()> {
        let mut output = HashValue::sha3_256_of(challenge);
        for _ in 0..difficulty {
            output = HashValue::sha3_256_of(output.as_ref());
        }
        if output.as_ref() == alleged_solution {
            Ok(())
        } else {
            anyhow::bail!("Invalid solution");
        }
    }
}
