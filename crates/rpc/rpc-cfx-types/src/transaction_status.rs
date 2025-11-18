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
    // The transaction has not entered the packing pool because there are
    // unready transactions ahead of it (nonce gap or insufficient balance),
    // or the transaction's gas price is too low compared to the current
    // minimum price required for packing.
    NotEnterPackingPool,
}
