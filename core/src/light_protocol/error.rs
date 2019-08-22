// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp::DecoderError;

use crate::{
    message::MsgId,
    network::{self, NetworkContext, PeerId, UpdateNodeOperation},
};

error_chain! {
    links {
        Network(network::Error, network::ErrorKind);
    }

    foreign_links {
        Decoder(DecoderError);
    }

    errors {
        GenesisMismatch {
            description("Genesis mismatch"),
            display("Genesis mismatch"),
        }
        NoResponse {
            description("NoResponse"),
            display("NoResponse"),
        }

        InternalError {
            description("Internal error"),
            display("Internal error"),
        }

        InvalidMessageFormat {
            description("Invalid message format"),
            display("Invalid message format"),
        }

        InvalidLedgerProof {
            description("Invalid ledger proof"),
            display("Invalid ledger proof"),
        }

        InvalidReceipts {
            description("Invalid receipts"),
            display("Invalid receipts"),
        }

        InvalidStateProof {
            description("Invalid state proof"),
            display("Invalid state proof"),
        }

        InvalidStateRoot {
            description("Invalid state root"),
            display("Invalid state root"),
        }

        InvalidTxSignature {
            description("Invalid tx signature"),
            display("Invalid tx signature"),
        }

        PivotHashMismatch {
            description("Pivot hash mismatch"),
            display("Pivot hash mismatch"),
        }

        SendStatusFailed {
            description("Send status failed"),
            display("Send status failed"),
        }

        UnableToProduceProof {
            description("Unable to produce proof"),
            display("Unable to produce proof"),
        }

        UnexpectedMessage {
            description("Unexpected message"),
            display("Unexpected message"),
        }

        UnexpectedPeerType {
            description("Unexpected peer type"),
            display("Unexpected peer type"),
        }

        UnexpectedRequestId {
            description("Unexpected request id"),
            display("Unexpected request id"),
        }

        UnexpectedResponse {
            description("Unexpected response"),
            display("Unexpected response"),
        }

        UnknownMessage {
            description("Unknown message"),
            display("Unknown message"),
        }

        UnknownPeer {
            description("Unknown peer"),
            display("Unknown peer"),
        }

        ValidationFailed {
            description("Validation failed"),
            display("Validation failed"),
        }
    }
}

pub fn handle(io: &dyn NetworkContext, peer: PeerId, msg_id: MsgId, e: Error) {
    warn!(
        "Error while handling message, peer={}, msg_id={:?}, error={:?}",
        peer, msg_id, e
    );

    let mut disconnect = true;
    let mut op = None;

    // NOTE: do not use wildcard; this way, the compiler
    // will help covering all the cases.
    match e.0 {
        ErrorKind::NoResponse
        | ErrorKind::InternalError

        // NOTE: we should be tolerant of non-critical errors,
        // e.g. do not disconnect on requesting non-existing epoch
        | ErrorKind::Msg(_)

        // NOTE: this can happen in normal scenarios
        // where the pivot chain has not converged
        | ErrorKind::PivotHashMismatch

        // NOTE: in order to let other protocols run,
        // we should not disconnect on protocol failure
        | ErrorKind::SendStatusFailed

        // NOTE: if we do not have a confirmed (non-blamed) block
        // with the info needed to produce a state root proof, we
        // should not disconnect the peer
        | ErrorKind::UnableToProduceProof

        // NOTE: to help with backward-compatibility, we
        // should not disconnect on `UnknownMessage`
        | ErrorKind::UnknownMessage => disconnect = false,

        ErrorKind::GenesisMismatch
        | ErrorKind::UnexpectedMessage
        | ErrorKind::UnexpectedPeerType
        | ErrorKind::UnknownPeer => op = Some(UpdateNodeOperation::Failure),

        ErrorKind::UnexpectedRequestId | ErrorKind::UnexpectedResponse => {
            op = Some(UpdateNodeOperation::Demotion)
        }

        ErrorKind::InvalidMessageFormat
        | ErrorKind::InvalidLedgerProof
        | ErrorKind::InvalidReceipts
        | ErrorKind::InvalidStateProof
        | ErrorKind::InvalidStateRoot
        | ErrorKind::InvalidTxSignature
        | ErrorKind::ValidationFailed
        | ErrorKind::Decoder(_) => op = Some(UpdateNodeOperation::Remove),

        // network errors
        ErrorKind::Network(kind) => match kind {
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

        ErrorKind::__Nonexhaustive {} => {
            op = Some(UpdateNodeOperation::Failure)
        }
    };

    if disconnect {
        io.disconnect_peer(peer, op, None);
    }
}
