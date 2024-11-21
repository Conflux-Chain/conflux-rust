// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::storage::Error as StorageError;
use cfx_types::Address;
use primitives::account::AccountError;
use rlp::DecoderError;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Account(#[from] AccountError),

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Decoder(#[from] DecoderError),

    #[error("incomplete database: address={0:?}")]
    IncompleteDatabase(Address),

    #[error("PoS database error, err={0:?}")]
    PosDatabaseError(String),

    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<String> for Error {
    fn from(e: String) -> Self { Error::Msg(e) }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self { Error::Msg(e.into()) }
}
