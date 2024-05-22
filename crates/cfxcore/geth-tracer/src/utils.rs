//! Util functions for revm related ops
use alloy_primitives::{hex, B256};
use alloy_sol_types::{ContractError, GenericRevertReason};
use cfx_types::{Address, H160, H256, U256};
use cfx_vm_interpreter::instructions::{INSTRUCTIONS, INSTRUCTIONS_CANCUN};
use revm::primitives::{Address as RAddress, U256 as RU256};

/// creates the memory data in 32byte chunks
/// see <https://github.com/ethereum/go-ethereum/blob/366d2169fbc0e0f803b68c042b77b6b480836dbc/eth/tracers/logger/logger.go#L450-L452>
#[inline]
pub(crate) fn convert_memory(data: &[u8]) -> Vec<String> {
    let mut memory = Vec::with_capacity((data.len() + 31) / 32);
    for idx in (0..data.len()).step_by(32) {
        let len = std::cmp::min(idx + 32, data.len());
        memory.push(hex::encode(&data[idx..len]));
    }
    memory
}

/// Get the gas used, accounting for refunds
#[inline]
pub(crate) fn gas_used(spent: u64, refunded: u64) -> u64 {
    let refund_quotient = 5;
    spent - (refunded).min(spent / refund_quotient)
}

/// Returns a non empty revert reason if the output is a revert/error.
#[inline]
pub(crate) fn maybe_revert_reason(output: &[u8]) -> Option<String> {
    let reason = match GenericRevertReason::decode(output)? {
        GenericRevertReason::ContractError(err) => {
            match err {
                // return the raw revert reason and don't use the revert's
                // display message
                ContractError::Revert(revert) => revert.reason,
                err => err.to_string(),
            }
        }
        GenericRevertReason::RawString(err) => err,
    };
    if reason.is_empty() {
        None
    } else {
        Some(reason)
    }
}

/// Returns the number of items pushed on the stack by a given opcode.
/// This used to determine how many stack etries to put in the `push` element
/// in a parity vmTrace.
/// The value is obvious for most opcodes, but SWAP* and DUP* are a bit weird,
/// and we handle those as they are handled in parity vmtraces.
/// For reference: <https://github.com/ledgerwatch/erigon/blob/9b74cf0384385817459f88250d1d9c459a18eab1/turbo/jsonrpc/trace_adhoc.go#L451>
pub(crate) fn stack_push_count(step_op: u8, cancun_enabled: bool) -> usize {
    match cancun_enabled {
        true => match INSTRUCTIONS_CANCUN.get(step_op as usize) {
            Some(Some(instruct)) => instruct.ret,
            _ => 0,
        },
        false => match INSTRUCTIONS.get(step_op as usize) {
            Some(Some(instruct)) => instruct.ret,
            _ => 0,
        },
    }
}

// convert from cfx U256 to alloy U256
pub fn to_alloy_u256(u: U256) -> RU256 {
    let mut be_bytes: [u8; 32] = [0; 32];
    u.to_big_endian(&mut be_bytes);
    RU256::from_be_bytes(be_bytes)
}

pub fn to_alloy_address(h: H160) -> RAddress {
    RAddress::from_slice(h.as_bytes())
}

pub fn to_alloy_h256(h: H256) -> B256 { B256::from(h.0) }

pub fn from_alloy_address(address: RAddress) -> Address {
    Address::from_slice(address.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::{GenericContractError, SolInterface};

    #[test]
    fn decode_revert_reason() {
        let err = GenericContractError::Revert("my revert".into());
        let encoded = err.abi_encode();
        let reason = maybe_revert_reason(&encoded).unwrap();
        assert_eq!(reason, "my revert");
    }

    // <https://etherscan.io/tx/0x105707c8e3b3675a8424a7b0820b271cbe394eaf4d5065b03c273298e3a81314>
    #[test]
    fn decode_revert_reason_with_error() {
        let err = hex!("08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024556e697377617056323a20494e53554646494349454e545f494e5055545f414d4f554e5400000000000000000000000000000000000000000000000000000080");
        let reason = maybe_revert_reason(&err[..]).unwrap();
        assert_eq!(reason, "UniswapV2: INSUFFICIENT_INPUT_AMOUNT");
    }
}
