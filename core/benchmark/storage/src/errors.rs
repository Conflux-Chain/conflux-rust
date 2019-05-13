use error_chain::*;
use std::io;

error_chain! {
    links {
    }

    foreign_links {
        Io(io::Error);
        RlpDecodeError(::rlp::DecoderError);
        SerdeError(::serde_json::error::Error);
        EthKeyError(::ethkey::Error);
    }

    errors {
    }
}
