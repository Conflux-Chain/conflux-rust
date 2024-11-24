// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId, RequestId},
    sync::message::Throttled,
    NodeType,
};
use cfx_internal_common::ChainIdParamsOneChainInner;
use cfx_types::{H160, H256};
use network::{node_table::NodeId, NetworkContext, UpdateNodeOperation};
use parking_lot::Mutex;
use primitives::{account::AccountError, filter::FilterError, StateRoot};
use rlp::DecoderError;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Network(#[from] network::Error),
    #[error(transparent)]
    StateDb(#[from] cfx_statedb::Error),
    #[error(transparent)]
    Storage(#[from] cfx_storage::Error),
    #[error(transparent)]
    Decoder(#[from] DecoderError),
    #[error(transparent)]
    Filter(#[from] FilterError),
    #[error(transparent)]
    AccountError(#[from] AccountError),
    #[error("packet already throttled: {0:?}")]
    AlreadyThrottled(&'static str),
    #[error("ChainId mismatch, ours={ours:?}, theirs={theirs:?}.")]
    ChainIdMismatch {
        ours: ChainIdParamsOneChainInner,
        theirs: ChainIdParamsOneChainInner,
    },
    #[error("{:?}", .0.display_error())]
    ClonableErrorWrapper(ClonableError),
    #[error("Genesis mismatch, ours={ours:?}, theirs={theirs:?}.")]
    GenesisMismatch { ours: H256, theirs: H256 },
    #[error("Internal error: {0:?}")]
    InternalError(String),
    #[error("Logs bloom hash validation for epoch {epoch} failed, expected={expected:?}, received={received:?}")]
    InvalidBloom {
        epoch: u64,
        expected: H256,
        received: H256,
    },
    #[error("Header verification failed")]
    InvalidHeader,
    #[error("Invalid ledger proof size for header {hash:?}: expected={expected}, received={received}")]
    InvalidLedgerProofSize {
        hash: H256,
        expected: u64,
        received: u64,
    },
    #[error("Invalid message format")]
    InvalidMessageFormat,
    #[error("Invalid previous state root for epoch {current_epoch} with snapshot epoch count {snapshot_epoch_count}: {root:?}")]
    InvalidPreviousStateRoot {
        current_epoch: u64,
        snapshot_epoch_count: u64,
        root: Option<StateRoot>,
    },
    #[error("Receipts root validation for epoch {epoch} failed, expected={expected:?}, received={received:?}")]
    InvalidReceipts {
        epoch: u64,
        expected: H256,
        received: H256,
    },
    #[error(
        "Invalid state proof for key {value:?} and value {key:?} in epoch {epoch}: {reason:?}"
    )]
    InvalidStateProof {
        epoch: u64,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
        reason: &'static str,
        #[source]
        source: Option<Box<Error>>,
    },
    #[error("State root validation for epoch {epoch} failed, expected={expected:?}, received={received:?}")]
    InvalidStateRoot {
        epoch: u64,
        expected: H256,
        received: H256,
    },
    #[error("Invalid storage root proof for address {address:?} in epoch {epoch}: {reason}")]
    InvalidStorageRootProof {
        epoch: u64,
        address: H160,
        reason: &'static str,
        #[source]
        source: Option<Box<Error>>,
    },
    #[error("Invalid tx info: {reason:?}")]
    InvalidTxInfo { reason: String },
    #[error("Transaction root validation for block {hash:?} failed, expected={expected:?}, received={received:?}")]
    InvalidTxRoot {
        hash: H256,
        expected: H256,
        received: H256,
    },
    #[error("Invalid signature for transaction {hash:?}")]
    InvalidTxSignature { hash: H256 },
    #[error("Witness root validation for header {hash:?} failed, expected={expected:?}, received={received:?}")]
    InvalidWitnessRoot {
        hash: H256,
        expected: H256,
        received: H256,
    },
    #[error("Failed to send status to peer {peer:?}")]
    SendStatusFailed {
        peer: NodeId,
        #[source]
        source: Option<Box<Error>>,
    },
    #[error("Operation timeout: {0:?}")]
    Timeout(String),
    #[error("packet {0:?} throttled: {1:?}")]
    Throttled(&'static str, Throttled),
    #[error("Unable to produce tx info: {reason:?}")]
    UnableToProduceTxInfo { reason: String },
    #[error(
        "Unexpected message id={received:?}, expected one of {expected:?}"
    )]
    UnexpectedMessage {
        expected: Vec<MsgId>,
        received: MsgId,
    },
    #[error("Unexpected peer type: {node_type:?}")]
    UnexpectedPeerType { node_type: NodeType },
    #[error("Unexpected response id; expected = {expected:?}, received = {received:?}")]
    UnexpectedResponse {
        expected: Option<RequestId>,
        received: RequestId,
    },
    #[error("Unknown message: {id:?}")]
    UnknownMessage { id: MsgId },
    #[error("Witness for epoch {epoch} is not available")]
    WitnessUnavailable { epoch: u64 },
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn handle(
    io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, e: &Error,
) {
    // for clonable errors, we will print the error in the recursive call
    if !matches!(e, Error::ClonableErrorWrapper(_)) {
        warn!(
            "Error while handling message, peer={}, msg_id={:?}, error={}",
            peer, msg_id, e,
        );
    }

    let mut disconnect = true;
    let reason = format!("{}", e);
    let mut op = None;

    // NOTE: do not use wildcard; this way, the compiler
    // will help covering all the cases.
    match &e {
        // for wrapped errors, handle based on the inner error
        Error::ClonableErrorWrapper(e) => {
            handle(io, peer, msg_id, &*e.0.lock());

            // if we need to disconnect, we will do it in the call above
            disconnect = false
        }

        Error::Filter(_)
        | Error::InternalError(_)

        // NOTE: we should be tolerant of non-critical errors,
        // e.g. do not disconnect on requesting non-existing epoch
        | Error::Msg(_)

        // NOTE: in order to let other protocols run,
        // we should not disconnect on protocol failure
        | Error::SendStatusFailed{..}

        | Error::Timeout(_)

        // if the tx requested has been removed locally,
        // we should not disconnect the peer
        | Error::UnableToProduceTxInfo{..}

        // if the witness is not available, it is probably
        // due to the local witness sync process
        | Error::WitnessUnavailable{..}

        // NOTE: to help with backward-compatibility, we
        // should not disconnect on `UnknownMessage`
        | Error::UnknownMessage{..} => disconnect = false,


        Error::GenesisMismatch{..}
        | Error::InvalidHeader
        | Error::ChainIdMismatch{..}
        | Error::UnexpectedMessage{..}
        | Error::UnexpectedPeerType{..} => op = Some(UpdateNodeOperation::Failure),

        Error::UnexpectedResponse{..} => {
            op = Some(UpdateNodeOperation::Demotion)
        }

        Error::InvalidBloom{..}
        | Error::InvalidLedgerProofSize{..}
        | Error::InvalidMessageFormat
        | Error::InvalidPreviousStateRoot{..}
        | Error::InvalidReceipts{..}
        | Error::InvalidStateProof{..}
        | Error::InvalidStateRoot{..}
        | Error::InvalidStorageRootProof{..}
        | Error::InvalidTxInfo{..}
        | Error::InvalidTxRoot{..}
        | Error::InvalidTxSignature{..}
        | Error::InvalidWitnessRoot{..}
        | Error::AlreadyThrottled(_)
        | Error::Decoder(_)
        | Error::AccountError(_) => op = Some(UpdateNodeOperation::Remove),

        Error::Throttled(_, resp) => {
            disconnect = false;

            if let Err(e) = resp.send(io, peer) {
                error!("failed to send throttled packet: {:?}", e);
                disconnect = true;
            }
        }

        // network errors
        Error::Network(kind) => match kind {
            network::Error::SendUnsupportedMessage{..} => {
                unreachable!("This is a bug in protocol version maintenance. {:?}", kind);
            }

            network::Error::MessageDeprecated{..} => {
                op = Some(UpdateNodeOperation::Failure);
                error!(
                    "Peer sent us a deprecated message {:?}. Either it's a bug \
                    in protocol version maintenance or the peer is malicious.",
                    kind,
                );
            }

            network::Error::AddressParse
            | network::Error::AddressResolve(_)
            | network::Error::Auth
            | network::Error::BadAddr
            | network::Error::Disconnect(_)
            | network::Error::Expired
            | network::Error::InvalidNodeId
            | network::Error::Io(_)
            | network::Error::OversizedPacket
            | network::Error::Throttling(_) => disconnect = false,

            network::Error::BadProtocol | network::Error::Decoder(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }

            network::Error::SocketIo(_) | network::Error::Msg(_) => {
                op = Some(UpdateNodeOperation::Failure)
            }
        },

        Error::StateDb(_)| Error::Storage(_) => disconnect = false,

        // Error::__Nonexhaustive {} => {
        //     op = Some(UpdateNodeOperation::Failure)
        // }
    };

    if disconnect {
        io.disconnect_peer(peer, op, reason.as_str());
    }
}

#[derive(Clone, Debug)]
pub struct ClonableError(Arc<Mutex<Error>>);

impl Into<Error> for ClonableError {
    fn into(self) -> Error { Error::ClonableErrorWrapper(self).into() }
}

impl From<Error> for ClonableError {
    fn from(e: Error) -> ClonableError {
        ClonableError(Arc::new(Mutex::new(e)))
    }
}

impl ClonableError {
    fn display_error(&self) -> String { self.0.lock().to_string() }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self { Error::Msg(e.into()) }
}
impl From<String> for Error {
    fn from(e: String) -> Self { Error::Msg(e) }
}
