extern crate cfx_types;
extern crate revm_primitives as alloy_types;

pub fn from_alloy_address(address: alloy_types::Address) -> cfx_types::Address {
    cfx_types::H160(address.0 .0)
}

pub fn to_alloy_address(address: cfx_types::Address) -> alloy_types::Address {
    alloy_types::Address(alloy_types::FixedBytes(address.0))
}

pub fn from_alloy_u256(value: alloy_types::U256) -> cfx_types::U256 {
    // SAFETY: `alloy_types::U256` has a single field of type `[u64; 4]` with
    // `repr(transparent)`.
    let dwords =
        unsafe { std::mem::transmute::<alloy_types::U256, [u64; 4]>(value) };
    cfx_types::U256(dwords)
}

pub fn to_alloy_u256(value: cfx_types::U256) -> alloy_types::U256 {
    // SAFETY: `alloy_types::U256` has a single field of type `[u64; 4]` with
    // `repr(transparent)`.
    unsafe { std::mem::transmute::<[u64; 4], alloy_types::U256>(value.0) }
}

pub fn from_alloy_h256(value: alloy_types::B256) -> cfx_types::H256 {
    cfx_types::H256(value.0)
}

pub fn to_alloy_h256(value: cfx_types::H256) -> alloy_types::B256 {
    alloy_types::FixedBytes(value.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_address_conversions() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let random_bytes: [u8; 20] = rng.gen();
            let alloy_address =
                alloy_types::Address(alloy_types::FixedBytes(random_bytes));
            let cfx_address = cfx_types::H160(random_bytes);

            assert_eq!(from_alloy_address(alloy_address), cfx_address);
            assert_eq!(to_alloy_address(cfx_address), alloy_address);
        }
    }

    #[test]
    fn test_u256_conversions() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let random_bytes: [u8; 32] = rng.gen();
            let alloy_u256 = alloy_types::U256::from_be_bytes(random_bytes);
            let cfx_u256 = cfx_types::U256::from(random_bytes);

            assert_eq!(from_alloy_u256(alloy_u256), cfx_u256);
            assert_eq!(to_alloy_u256(cfx_u256), alloy_u256);
        }
    }

    #[test]
    fn test_h256_conversions() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let random_bytes: [u8; 32] = rng.gen();
            let alloy_h256 = alloy_types::B256::from(random_bytes);
            let cfx_h256 = cfx_types::H256(random_bytes);

            assert_eq!(from_alloy_h256(alloy_h256), cfx_h256);
            assert_eq!(to_alloy_h256(cfx_h256), alloy_h256);
        }
    }

    #[test]
    fn test_roundtrip_conversions() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            // Address roundtrip
            let random_address_bytes: [u8; 20] = rng.gen();
            let original_address = alloy_types::Address(
                alloy_types::FixedBytes(random_address_bytes),
            );
            let roundtrip_address =
                to_alloy_address(from_alloy_address(original_address));
            assert_eq!(original_address, roundtrip_address);

            // U256 roundtrip
            let random_u256_bytes: [u8; 32] = rng.gen();
            let original_u256 =
                alloy_types::U256::from_be_bytes(random_u256_bytes);
            let roundtrip_u256 = to_alloy_u256(from_alloy_u256(original_u256));
            assert_eq!(original_u256, roundtrip_u256);

            // H256 roundtrip
            let random_h256_bytes: [u8; 32] = rng.gen();
            let original_h256 = alloy_types::B256::from(random_h256_bytes);
            let roundtrip_h256 = to_alloy_h256(from_alloy_h256(original_h256));
            assert_eq!(original_h256, roundtrip_h256);
        }
    }
}
