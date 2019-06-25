// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::error::BlockError;
use network;
use rlp::DecoderError;

error_chain! {
    links {
        Network(network::Error, network::ErrorKind);
    }

    foreign_links {
        Block(BlockError) #[doc = "Error concerning block processing."];
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
    }
}
