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
        Invalid {
            description("Invalid block"),
            display("Invalid block"),
        }

        UnknownPeer {
            description("Unknown peer"),
            display("Unknown peer"),
        }

        UnexpectedResponse {
            description("Unexpected response"),
            display("Unexpected response"),
        }

        TooManyTrans {
            description("Send too many transactions to node in catch-up mode"),
            display("Sent too many transactions"),
        }

        InvalidTimestamp {
            description("Peer timestamp drifts too much"),
            display("Drift too much"),
        }
    }
}
