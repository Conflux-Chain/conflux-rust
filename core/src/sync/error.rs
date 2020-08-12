// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::message::Throttled;
use futures::channel::oneshot;
use network;
use rlp::DecoderError;
use std::io;

error_chain! {
    links {
        Network(network::Error, network::ErrorKind);
        Storage(cfx_storage::Error, cfx_storage::ErrorKind);
    }

    foreign_links {
        Decoder(DecoderError);
        Io(io::Error);
    }

    errors {
        InvalidBlock {
            description("Invalid block"),
            display("Invalid block"),
        }

        InvalidGetBlockTxn(reason: String) {
            description("Invalid GetBlockTxn"),
            display("Invalid GetBlockTxn: {}", reason),
        }

        InvalidMessageFormat {
            description("Invalid message format"),
            display("Invalid message format"),
        }

        InvalidStatus(reason: String) {
            description("Invalid Status"),
            display("Invalid Status: {}", reason),
        }

        UnknownPeer {
            description("Unknown peer"),
            display("Unknown peer"),
        }

        UnexpectedResponse {
            description("Unexpected response"),
            display("Unexpected response"),
        }

        RequestNotFound {
            description("The response is received after the request timeout or \
            there is no request matching the response"),
            display("No matching request found for response"),
        }

        TooManyTrans {
            description("Send too many transactions to node in catch-up mode"),
            display("Sent too many transactions"),
        }

        RpcTimeout {
            description("Rpc gets timeout"),
            display("Rpc gets timeout"),
        }

        RpcCancelledByDisconnection {
            description("Rpc gets cancelled by disconnection"),
            display("Rpc gets cancelled by disconnection"),
        }

        InvalidTimestamp {
            description("Peer timestamp drifts too much"),
            display("Drift too much"),
        }

        InvalidSnapshotManifest(reason: String) {
            description("invalid snapshot manifest"),
            display("invalid snapshot manifest: {}", reason),
        }

        InvalidSnapshotChunk(reason: String) {
            description("invalid snapshot chunk"),
            display("invalid snapshot chunk: {}", reason),
        }

        // FIXME: This works as a compatible fix when the snapshot provider cannot serve the chunk.
        // We should add another reply like `UnsupportedSnapshot` and remove this.
        EmptySnapshotChunk {
            description("empty snapshot chunk")
            display("Receive an empty snapshot chunk response, retry later")
        }

        AlreadyThrottled(msg_name: &'static str) {
            description("packet already throttled"),
            display("packet already throttled: {:?}", msg_name),
        }

        Throttled(msg_name: &'static str, response: Throttled) {
            description("packet throttled"),
            display("packet {:?} throttled: {:?}", msg_name, response),
        }

        InCatchUpMode(reason: String) {
            description("Cannot process the message due to the catch up mode."),
            display("Cannot process the message due to the catch up mode: {:?}", reason),
        }

        InternalError(reason: String) {
            description("Internal error"),
            display("Internal error: {:?}", reason),
        }

        UnexpectedMessage(reason: String) {
            description("Message received in unexpected"),
            display("UnexpectedMessage: {:?}", reason),
        }

        NotSupported(reason: String) {
            description("Unable to process the message due to protocol version mismatch"),
            display("Unable to process the message due to protocol version mismatch: {}", reason),
        }
    }
}

impl From<oneshot::Canceled> for Error {
    fn from(error: oneshot::Canceled) -> Self {
        ErrorKind::InternalError(format!("{}", error)).into()
    }
}
