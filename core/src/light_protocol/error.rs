// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    message::{Message, MsgId, RequestId},
    sync::message::Throttled,
    NodeType,
};
use cfx_types::{H160, H256};
use error_chain::ChainedError;
use network::{node_table::NodeId, NetworkContext, UpdateNodeOperation};
use parking_lot::Mutex;
use primitives::{filter::FilterError, ChainIdParams, StateRoot};
use rlp::DecoderError;
use std::sync::Arc;

error_chain! {
    links {
        Network(network::Error, network::ErrorKind);
        StateDb(cfx_statedb::Error, cfx_statedb::ErrorKind);
    }

    foreign_links {
        Decoder(DecoderError);
        Filter(FilterError);
    }

    errors {
        AlreadyThrottled(msg_name: &'static str) {
            description("packet already throttled"),
            display("packet already throttled: {:?}", msg_name),
        }

        ChainIdMismatch{ ours: ChainIdParams, theirs: ChainIdParams } {
            description("ChainId mismatch"),
            display("ChainId mismatch, ours={:?}, theirs={:?}.", ours, theirs),
        }

        ClonableErrorWrapper(error: ClonableError) {
            description("Clonable error"),
            display("{:?}", error.0.lock().to_string()),
        }

        GenesisMismatch{ ours: H256, theirs: H256 } {
            description("Genesis mismatch"),
            display("Genesis mismatch, ours={:?}, theirs={:?}.", ours, theirs),
        }

        InternalError(details: String) {
            description("Internal error"),
            display("Internal error: {:?}", details),
        }

        InvalidBloom{ epoch: u64, expected: H256, received: H256 } {
            description("Logs bloom hash validation failed"),
            display("Logs bloom hash validation for epoch {} failed, expected={:?}, received={:?}", epoch, expected, received),
        }

        InvalidLedgerProofSize{ hash: H256, expected: u64, received: u64 } {
            description("Invalid ledger proof size"),
            display("Invalid ledger proof size for header {:?}: expected={}, received={}", hash, expected, received),
        }

        InvalidMessageFormat {
            description("Invalid message format"),
            display("Invalid message format"),
        }

        InvalidPreviousStateRoot{ current_epoch: u64, snapshot_epoch_count: u64, root: Option<StateRoot> } {
            description("Invalid previous state root"),
            display("Invalid previous state root for epoch {} with snapshot epoch count {}: {:?}", current_epoch, snapshot_epoch_count, root),
        }

        InvalidReceipts{ epoch: u64, expected: H256, received: H256 } {
            description("Receipts root validation failed"),
            display("Receipts root validation for epoch {} failed, expected={:?}, received={:?}", epoch, expected, received),
        }

        InvalidStateProof{ epoch: u64, key: Vec<u8>, value: Option<Vec<u8>>, reason: &'static str } {
            description("Invalid state proof"),
            display("Invalid state proof for key {:?} and value {:?} in epoch {}: {:?}", value, key, epoch, reason),
        }

        InvalidStateRoot{ epoch: u64, expected: H256, received: H256 } {
            description("State root validation failed"),
            display("State root validation for epoch {} failed, expected={:?}, received={:?}", epoch, expected, received),
        }

        InvalidStorageRootProof{ epoch: u64, address: H160, reason: &'static str } {
            description("Invalid storage root proof"),
            display("Invalid storage root proof for address {:?} in epoch {}: {}", address, epoch, reason),
        }

        InvalidTxInfo{ reason: String } {
            description("Invalid tx info"),
            display("Invalid tx info: {:?}", reason),
        }

        InvalidTxRoot{ hash: H256, expected: H256, received: H256 } {
            description("Transaction root validation failed"),
            display("Transaction root validation for block {:?} failed, expected={:?}, received={:?}", hash, expected, received),
        }

        InvalidTxSignature{ hash: H256 } {
            description("Invalid tx signature"),
            display("Invalid signature for transaction {:?}", hash),
        }

        InvalidWitnessRoot{ hash: H256, expected: H256, received: H256 } {
            description("Witness root validation failed"),
            display("Witness root validation for header {:?} failed, expected={:?}, received={:?}", hash, expected, received),
        }

        SendStatusFailed{ peer: NodeId } {
            description("Send status failed"),
            display("Failed to send status to peer {:?}", peer),
        }

        Timeout(details: String) {
            description("Operation timeout"),
            display("Operation timeout: {:?}", details),
        }

        Throttled(msg_name: &'static str, response: Throttled) {
            description("packet throttled"),
            display("packet {:?} throttled: {:?}", msg_name, response),
        }

        UnableToProduceTxInfo{ reason: String } {
            description("Unable to produce tx info"),
            display("Unable to produce tx info: {:?}", reason),
        }

        UnexpectedMessage{ expected: Vec<MsgId>, received: MsgId } {
            description("Unexpected message"),
            display("Unexpected message id={:?}, expected one of {:?}", received, expected),
        }

        UnexpectedPeerType{ node_type: NodeType } {
            description("Unexpected peer type"),
            display("Unexpected peer type: {:?}", node_type),
        }

        UnexpectedResponse{ expected: Option<RequestId>, received: RequestId } {
            description("Unexpected response"),
            display("Unexpected response id; expected = {:?}, received = {:?}", expected, received),
        }

        UnknownMessage{ id: MsgId } {
            description("Unknown message"),
            display("Unknown message: {:?}", id),
        }

        WitnessUnavailable{ epoch: u64 } {
            description("Witness unavailable"),
            display("Witness for epoch {} is not available", epoch),
        }
    }
}

pub fn handle(
    io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, e: &Error,
) {
    // for clonable errors, we will print the error in the recursive call
    if !matches!(e.0, ErrorKind::ClonableErrorWrapper(_)) {
        warn!(
            "Error while handling message, peer={}, msg_id={:?}, error={}",
            peer,
            msg_id,
            e.display_chain().to_string(),
        );
    }

    let mut disconnect = true;
    let reason = format!("{}", e.0);
    let mut op = None;

    // NOTE: do not use wildcard; this way, the compiler
    // will help covering all the cases.
    match &e.0 {
        // for wrapped errors, handle based on the inner error
        ErrorKind::ClonableErrorWrapper(e) => {
            handle(io, peer, msg_id, &*e.0.lock());

            // if we need to disconnect, we will do it in the call above
            disconnect = false
        }

        ErrorKind::Filter(_)
        | ErrorKind::InternalError(_)

        // NOTE: we should be tolerant of non-critical errors,
        // e.g. do not disconnect on requesting non-existing epoch
        | ErrorKind::Msg(_)

        // NOTE: in order to let other protocols run,
        // we should not disconnect on protocol failure
        | ErrorKind::SendStatusFailed{..}

        | ErrorKind::Timeout(_)

        // if the tx requested has been removed locally,
        // we should not disconnect the peer
        | ErrorKind::UnableToProduceTxInfo{..}

        // if the witness is not available, it is probably
        // due to the local witness sync process
        | ErrorKind::WitnessUnavailable{..}

        // NOTE: to help with backward-compatibility, we
        // should not disconnect on `UnknownMessage`
        | ErrorKind::UnknownMessage{..} => disconnect = false,


        ErrorKind::GenesisMismatch{..}
        | ErrorKind::ChainIdMismatch{..}
        | ErrorKind::UnexpectedMessage{..}
        | ErrorKind::UnexpectedPeerType{..} => op = Some(UpdateNodeOperation::Failure),

        ErrorKind::UnexpectedResponse{..} => {
            op = Some(UpdateNodeOperation::Demotion)
        }

        ErrorKind::InvalidBloom{..}
        | ErrorKind::InvalidLedgerProofSize{..}
        | ErrorKind::InvalidMessageFormat
        | ErrorKind::InvalidPreviousStateRoot{..}
        | ErrorKind::InvalidReceipts{..}
        | ErrorKind::InvalidStateProof{..}
        | ErrorKind::InvalidStateRoot{..}
        | ErrorKind::InvalidStorageRootProof{..}
        | ErrorKind::InvalidTxInfo{..}
        | ErrorKind::InvalidTxRoot{..}
        | ErrorKind::InvalidTxSignature{..}
        | ErrorKind::InvalidWitnessRoot{..}
        | ErrorKind::AlreadyThrottled(_)
        | ErrorKind::Decoder(_) => op = Some(UpdateNodeOperation::Remove),

        ErrorKind::Throttled(_, resp) => {
            disconnect = false;

            if let Err(e) = resp.send(io, peer) {
                error!("failed to send throttled packet: {:?}", e);
                disconnect = true;
            }
        }

        // network errors
        ErrorKind::Network(kind) => match kind {
            network::ErrorKind::SendUnsupportedMessage{..} => {
                unreachable!("This is a bug in protocol version maintenance. {:?}", kind);
            }

            network::ErrorKind::MessageDeprecated{..} => {
                op = Some(UpdateNodeOperation::Failure);
                error!(
                    "Peer sent us a deprecated message {:?}. Either it's a bug \
                    in protocol version maintenance or the peer is malicious.",
                    kind,
                );
            }

            network::ErrorKind::AddressParse
            | network::ErrorKind::AddressResolve(_)
            | network::ErrorKind::Auth
            | network::ErrorKind::BadAddr
            | network::ErrorKind::Disconnect(_)
            | network::ErrorKind::Expired
            | network::ErrorKind::InvalidNodeId
            | network::ErrorKind::Io(_)
            | network::ErrorKind::OversizedPacket
            | network::ErrorKind::Throttling(_) => disconnect = false,

            network::ErrorKind::BadProtocol | network::ErrorKind::Decoder => {
                op = Some(UpdateNodeOperation::Remove)
            }

            network::ErrorKind::SocketIo(_)
            | network::ErrorKind::Msg(_)
            | network::ErrorKind::__Nonexhaustive {} => {
                op = Some(UpdateNodeOperation::Failure)
            }
        },

        ErrorKind::StateDb(_) => disconnect = false,

        ErrorKind::__Nonexhaustive {} => {
            op = Some(UpdateNodeOperation::Failure)
        }
    };

    if disconnect {
        io.disconnect_peer(peer, op, reason.as_str());
    }
}

#[derive(Clone, Debug)]
pub struct ClonableError(Arc<Mutex<Error>>);

impl Into<Error> for ClonableError {
    fn into(self) -> Error { ErrorKind::ClonableErrorWrapper(self).into() }
}

impl From<Error> for ClonableError {
    fn from(e: Error) -> ClonableError {
        ClonableError(Arc::new(Mutex::new(e)))
    }
}
