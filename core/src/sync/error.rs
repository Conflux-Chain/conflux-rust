// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::storage;
use network;
use rlp::DecoderError;
use std::io;

error_chain! {
    links {
        Network(network::Error, network::ErrorKind);
        Storage(storage::Error, storage::ErrorKind);
    }

    foreign_links {
        Decoder(DecoderError);
        Io(io::Error);
    }

    errors {
        Invalid {
            description("Invalid block"),
            display("Invalid block"),
        }

        InvalidMessageFormat {
            description("Invalid message format"),
            display("Invalid message format"),
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
            there is not request for the response"),
            display("Request not found for the respond"),
        }

        TooManyTrans {
            description("Send too many transactions to node in catch-up mode"),
            display("Sent too many transactions"),
        }

        InvalidTimestamp {
            description("Peer timestamp drifts too much"),
            display("Drift too much"),
        }

        InvalidSnapshotManifest(reason: String) {
            description("invalid snapshot manifest"),
            display("invalid snapshot manifest: {:?}", reason),
        }

        InvalidSnapshotChunk(reason: String) {
            description("invalid snapshot chunk"),
            display("invalid snapshot chunk: {:?}", reason),
        }
    }
}
