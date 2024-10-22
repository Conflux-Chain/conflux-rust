// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::Throttled;
use futures::channel::oneshot;
use network;
use rlp::DecoderError;
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Network(#[from] network::Error),
    #[error(transparent)]
    Storage(#[from] cfx_storage::Error),
    #[error(transparent)]
    Decoder(#[from] DecoderError),
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("Invalid block")]
    InvalidBlock,
    #[error("Invalid GetBlockTxn: {0}")]
    InvalidGetBlockTxn(String),
    #[error("Invalid message format")]
    InvalidMessageFormat,
    #[error("Invalid Status: {0}")]
    InvalidStatus(String),
    #[error("Unknown peer")]
    UnknownPeer,
    #[error("Unexpected response")]
    UnexpectedResponse,
    #[error("No matching request found for response")]
    RequestNotFound,
    #[error("Sent too many transactions")]
    TooManyTrans,
    #[error("Rpc gets timeout")]
    RpcTimeout,
    #[error("Rpc gets cancelled by disconnection")]
    RpcCancelledByDisconnection,
    #[error("Drift too much")]
    InvalidTimestamp,
    #[error("invalid snapshot manifest: {0}")]
    InvalidSnapshotManifest(String),
    #[error("invalid snapshot chunk: {0}")]
    InvalidSnapshotChunk(String),
    #[error("Receive an empty snapshot chunk response, retry later")]
    EmptySnapshotChunk,
    #[error("packet already throttled: {0:?}")]
    AlreadyThrottled(&'static str),
    #[error("packet {0:?} throttled: {1:?}")]
    Throttled(&'static str, Throttled),
    #[error("Cannot process the message due to the catch up mode: {0:?}")]
    InCatchUpMode(String),
    #[error("Internal error: {0:?}")]
    InternalError(String),
    #[error("UnexpectedMessage: {0:?}")]
    UnexpectedMessage(String),
    #[error(
        "Unable to process the message due to protocol version mismatch: {0}"
    )]
    NotSupported(String),
    #[error("error msg: {0}")]
    Msg(String),
}

impl From<oneshot::Canceled> for Error {
    fn from(error: oneshot::Canceled) -> Self {
        Error::InternalError(format!("{}", error)).into()
    }
}

impl From<String> for Error {
    fn from(s: String) -> Error { Error::Msg(s) }
}
