// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use network;
use rlp::DecoderError;

error_chain! {
    links {
        Network(network::Error, network::ErrorKind);
    }

    foreign_links {
        Decoder(DecoderError);
    }

    errors {
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

        InvalidProof {
            description("Invalid proof"),
            display("Invalid proof"),
        }

        InvalidStateRoot {
            description("Invalid state root"),
            display("Invalid state root"),
        }

        PivotHashMismatch {
            description("Pivot hash mismatch"),
            display("Pivot hash mismatch"),
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
