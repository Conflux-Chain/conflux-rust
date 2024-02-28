use error_chain::*;
use std::io;

error_chain! {
    links {
    }

    foreign_links {
        AccountError(::primitives::account::AccountError);
        ConfluxStorageError(::cfx_storage::Error);
        EthKeyError(::ethkey::Error);
        Io(io::Error);
        ParseIntError(std::num::ParseIntError);
        RlpDecodeError(::rlp::DecoderError);
        SerdeError(::serde_json::error::Error);
    }

    errors {
    }
}
