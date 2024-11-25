/// The MAX_GAS_CALL_REQUEST is used as max value of cfx_call or cfx_estimate's
/// gas value to prevent call_virtual consumes too much resource.
/// The tx_pool will reject the tx if the gas is larger than half of the block
/// gas limit. which is 30_000_000 before 1559, and 60_000_000 after 1559.
pub const MAX_GAS_CALL_REQUEST: u64 = 15_000_000;
