use serde::Serialize;

/// Transaction status in the transaction pool.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum TransactionStatus {
    Packed,
    Ready,
    Pending(PendingReason),
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum PendingReason {
    FutureNonce,
    NotEnoughCash,
    OldEpochHeight,
    // The tx status in the pool is inaccurate due to chain switch or sponsor
    // balance change. This tx will not be packed even if it should have
    // been ready, and the user needs to send a new transaction to trigger
    // the status change.
    OutdatedStatus,
}
