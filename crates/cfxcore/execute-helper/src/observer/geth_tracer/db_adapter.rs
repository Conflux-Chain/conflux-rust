use super::utils::{convert_h256, convert_u256, to_h160};
use cfx_executor::state::State;
use cfx_statedb::Error as StateDbError;
use cfx_types::{AddressWithSpace, Space};
use revm::{
    db::{DatabaseRef, EmptyDB},
    primitives::{AccountInfo, Address, Bytecode, Bytes, B256, U256},
};
use std::{convert::Infallible, error, fmt};

// An adapter impl revm::db::DatabaseRef trait
pub struct RevmDbAdapter<'a> {
    state: &'a State,
    empty_db: EmptyDB,
    space: Space,
}

impl<'a> RevmDbAdapter<'a> {
    fn new(state: &'a State) -> Self {
        RevmDbAdapter {
            state,
            empty_db: EmptyDB::new(),
            space: Space::Ethereum, // default is ethereum
        }
    }
}

#[derive(Debug)]
pub enum RevmDbError {
    Custom(String),
}

impl error::Error for RevmDbError {}

impl fmt::Display for RevmDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "Custom: {s}"),
        }
    }
}

impl From<StateDbError> for RevmDbError {
    fn from(e: StateDbError) -> Self { RevmDbError::Custom(format!("{e}")) }
}

impl From<Infallible> for RevmDbError {
    fn from(e: Infallible) -> Self { RevmDbError::Custom(format!("{e}")) }
}

impl<'a> DatabaseRef for RevmDbAdapter<'a> {
    type Error = RevmDbError;

    /// Get basic account information.
    fn basic_ref(
        &self, address: Address,
    ) -> Result<Option<AccountInfo>, Self::Error> {
        let space_address = AddressWithSpace {
            address: to_h160(address),
            space: self.space,
        };
        let exist = self.state.exists(&space_address);
        if let Ok(true) = exist {
            let balance = self
                .state
                .balance(&space_address)
                .map(|v| convert_u256(v))?;

            let nonce = self.state.nonce(&space_address).map(|v| v.as_u64())?;

            let code_hash = self
                .state
                .code_hash(&space_address)
                .map(|v| convert_h256(v))?;

            // TODO code and code_hash need consider internal_contracts
            let _code = self.state.code(&space_address).map(|v| {
                v.map(|b| Bytecode::new_raw(Bytes::from(b.to_vec())))
            })?;

            let acc_info = AccountInfo {
                balance,
                nonce,
                code_hash,
                code: None,
            };
            return Ok(Some(acc_info));
        }

        self.empty_db.basic_ref(address).map_err(|e| e.into())
    }

    /// TODO(pana) Get account code by its hash.
    fn code_by_hash_ref(
        &self, code_hash: B256,
    ) -> Result<Bytecode, Self::Error> {
        self.empty_db
            .code_by_hash_ref(code_hash)
            .map_err(Into::into)
    }

    /// Get storage value of address at index.
    fn storage_ref(
        &self, address: Address, index: U256,
    ) -> Result<U256, Self::Error> {
        let space_address = AddressWithSpace {
            address: to_h160(address),
            space: self.space,
        };

        let key = index.to_be_bytes::<32>(); // TODO: check big endian is correct
        let result = self
            .state
            .storage_at(&space_address, &key)
            .map(|v| convert_u256(v))?;

        return Ok(result);
    }

    /// Get block hash by block number.
    /// unused
    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        let res = self.empty_db.block_hash_ref(number)?;

        Ok(res)
    }
}
