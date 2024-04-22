use std::path::Path;

use anyhow::Result;
use pkcs8::{
    AlgorithmIdentifier, EncryptedPrivateKeyDocument, ObjectIdentifier,
    PrivateKeyInfo,
};
use rand::{prelude::StdRng, rngs::OsRng, SeedableRng};
use serde::{de::DeserializeOwned, Serialize};

const OID: &str = "1.0.0";

// TODO(lpl): Store crypto parameters.
fn algorithm_identifier() -> AlgorithmIdentifier<'static> {
    AlgorithmIdentifier {
        oid: ObjectIdentifier::new(OID),
        parameters: None,
    }
}

/// Encrypt `pri_key` with `passwd`, and save it to `path`.
pub fn save_pri_key<P: AsRef<Path>, K: Serialize>(
    path: P, passwd: impl AsRef<[u8]>, pri_key: &K,
) -> Result<()> {
    let encoded_pri_keys = bcs::to_bytes(pri_key)?;
    let pri_key_info =
        PrivateKeyInfo::new(algorithm_identifier(), encoded_pri_keys.as_ref());
    let encrypted =
        pri_key_info.encrypt(StdRng::from_rng(OsRng).unwrap(), passwd)?;
    encrypted.write_der_file(path)?;
    Ok(())
}

/// Load `passwd` encrypted private key from `path`.
pub fn load_pri_key<'de, P: AsRef<Path>, K: DeserializeOwned>(
    path: P, passwd: impl AsRef<[u8]>,
) -> Result<K> {
    let encrypted = EncryptedPrivateKeyDocument::read_der_file(path)?;
    let encoded_keys = encrypted.decrypt(passwd)?;
    Ok(bcs::from_bytes(
        encoded_keys.private_key_info().private_key,
    )?)
}
