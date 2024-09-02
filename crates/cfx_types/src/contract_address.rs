use super::{Address, H256, U256};
use keccak_hash::keccak;
use rlp::RlpStream;

/// Specifies how an address is calculated for a new contract.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum CreateContractAddressType {
    /// Address is calculated from sender and nonce. Ethereum
    /// `create` scheme.
    FromSenderNonce,
    /// Address is calculated from sender, nonce, and code hash. Conflux
    /// `create` scheme.
    FromSenderNonceAndCodeHash,
    /// Address is calculated from block_hash, sender, nonce and code_hash.
    /// Potential new Conflux `create` scheme when kill_dust is enabled.
    FromBlockNumberSenderNonceAndCodeHash,
    /// Address is calculated from sender, salt and code hash. Conflux and
    /// Ethereum `create2` scheme.
    FromSenderSaltAndCodeHash(H256),
}

/// Calculate new contract address.
pub fn cal_contract_address(
    address_scheme: CreateContractAddressType, _block_number: u64,
    sender: &Address, nonce: &U256, code: &[u8],
) -> (Address, H256) {
    let code_hash = keccak(code);
    let (address, code_hash) = match address_scheme {
        CreateContractAddressType::FromSenderNonce => {
            let mut rlp = RlpStream::new_list(2);
            rlp.append(sender);
            rlp.append(nonce);
            let h = Address::from(keccak(rlp.as_raw()));
            (h, code_hash)
        }
        CreateContractAddressType::FromBlockNumberSenderNonceAndCodeHash => {
            unreachable!("Inactive setting");
            // let mut buffer = [0u8; 1 + 8 + 20 + 32 + 32];
            // let (lead_bytes, rest) = buffer.split_at_mut(1);
            // let (block_number_bytes, rest) = rest.split_at_mut(8);
            // let (sender_bytes, rest) =
            // rest.split_at_mut(Address::len_bytes());
            // let (nonce_bytes, code_hash_bytes) =
            //     rest.split_at_mut(H256::len_bytes());
            // // In Conflux, we take block_number and CodeHash into address
            // // calculation. This is required to enable us to clean
            // // up unused user account in future.
            // lead_bytes[0] = 0x0;
            // block_number.to_little_endian(block_number_bytes);
            // sender_bytes.copy_from_slice(&sender.address[..]);
            // nonce.to_little_endian(nonce_bytes);
            // code_hash_bytes.copy_from_slice(&code_hash[..]);
            // // In Conflux, we use the first four bits to indicate the type of
            // // the address. For contract address, the bits will be
            // // set to 0x8.
            // let mut h = Address::from(keccak(&buffer[..]));
            // h.set_contract_type_bits();
            // (h, code_hash)
        }
        CreateContractAddressType::FromSenderNonceAndCodeHash => {
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            // In Conflux, we append CodeHash to determine the address as well.
            // This is required to enable us to clean up unused user account in
            // future.
            buffer[0] = 0x0;
            buffer[1..(1 + 20)].copy_from_slice(&sender[..]);
            nonce.to_little_endian(&mut buffer[(1 + 20)..(1 + 20 + 32)]);
            buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first four bits to indicate the type of
            // the address. For contract address, the bits will be
            // set to 0x8.
            let h = Address::from(keccak(&buffer[..]));
            (h, code_hash)
        }
        CreateContractAddressType::FromSenderSaltAndCodeHash(salt) => {
            let mut buffer = [0u8; 1 + 20 + 32 + 32];
            buffer[0] = 0xff;
            buffer[1..(1 + 20)].copy_from_slice(&sender[..]);
            buffer[(1 + 20)..(1 + 20 + 32)].copy_from_slice(&salt[..]);
            buffer[(1 + 20 + 32)..].copy_from_slice(&code_hash[..]);
            // In Conflux, we use the first bit to indicate the type of the
            // address. For contract address, the bits will be set to 0x8.
            let h = Address::from(keccak(&buffer[..]));
            (h, code_hash)
        }
    };
    return (address, code_hash);
}
