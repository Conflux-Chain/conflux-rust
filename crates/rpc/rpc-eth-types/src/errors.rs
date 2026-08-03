use jsonrpsee::types::{
    error::{INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE},
    ErrorObjectOwned,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid params {0} {1}")]
    InvalidParams(String, String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<Error> for ErrorObjectOwned {
    fn from(e: Error) -> ErrorObjectOwned {
        match e {
            Error::InvalidParams(msg, details) => {
                ErrorObjectOwned::owned(INVALID_PARAMS_CODE, msg, Some(details))
            }
            Error::InternalError(msg) => {
                ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, msg, None::<()>)
            }
        }
    }
}
