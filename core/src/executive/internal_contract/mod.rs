// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod abi;
mod contracts;
mod impls;
pub mod sol_func;

use crate::{
    bytes::Bytes,
    hash::keccak,
    state::{State, Substate},
    vm::{self, ActionParams, GasLeft, Spec},
};
use cfx_types::{Address, H256};
use std::{collections::BTreeMap, sync::Arc};

use contracts::{internal_contract_factory, SolFnTable};

pub use self::{
    contracts::{
        ADMIN_CONTROL_CONTRACT_ADDRESS,
        SPONSOR_WHITELIST_CONTROL_CONTRACT_ADDRESS,
        STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS,
    },
    impls::suicide,
};

pub use self::abi::ABIDecodeError;
use self::abi::ABIReader;

lazy_static! {
    static ref INTERNAL_CONTRACT_CODE: Arc<Bytes> =
        Arc::new(vec![0u8, 0u8, 0u8, 0u8]);
    static ref INTERNAL_CONTRACT_CODE_HASH: H256 = keccak([0u8, 0u8, 0u8, 0u8]);
}

/// Native implementation of an internal contract.
pub trait InternalContractTrait: Send + Sync {
    /// Address of the internal contract
    fn address(&self) -> &Address;

    /// A hash-map for solidity function sig and execution handler.
    fn get_func_table(&self) -> &SolFnTable;

    /// execute this internal contract on the given parameters.
    fn execute(
        &self, params: &ActionParams, spec: &Spec, state: &mut State,
        substate: &mut Substate,
    ) -> vm::Result<GasLeft>
    {
        let mut input =
            ABIReader::new(params.data.as_ref().ok_or(ABIDecodeError)?.iter());

        let fn_sig = input.pull_sig()?;

        let solidity_fn = self
            .get_func_table()
            .get(&fn_sig)
            .ok_or(vm::Error::InternalContract("unsupported function"))?;

        solidity_fn.execute(input, params, spec, state, substate)
    }

    fn code(&self) -> Arc<Bytes> { INTERNAL_CONTRACT_CODE.clone() }

    fn code_hash(&self) -> H256 { *INTERNAL_CONTRACT_CODE_HASH }

    fn code_size(&self) -> usize { INTERNAL_CONTRACT_CODE.len() }
}

/// Native implementation of a solidity-interface function.
pub trait SolidityFunctionTrait: Send + Sync {
    fn execute(
        &self, input: ABIReader, params: &ActionParams, spec: &Spec,
        state: &mut State, substate: &mut Substate,
    ) -> vm::Result<GasLeft>;

    /// The string for function sig
    fn name(&self) -> &'static str;

    /// The function sig for this function
    fn function_sig(&self) -> [u8; 4] {
        let mut answer = [0u8; 4];
        answer.clone_from_slice(&keccak(self.name()).as_ref()[0..4]);
        answer
    }
}

pub struct InternalContractMap {
    builtin: Arc<BTreeMap<Address, Box<dyn InternalContractTrait>>>,
}

impl std::ops::Deref for InternalContractMap {
    type Target = Arc<BTreeMap<Address, Box<dyn InternalContractTrait>>>;

    fn deref(&self) -> &Self::Target { &self.builtin }
}

impl InternalContractMap {
    pub fn new() -> Self {
        let mut builtin = BTreeMap::new();
        let admin = internal_contract_factory("admin");
        let sponsor = internal_contract_factory("sponsor");
        let staking = internal_contract_factory("staking");
        builtin.insert(*admin.address(), admin);
        builtin.insert(*sponsor.address(), sponsor);
        builtin.insert(*staking.address(), staking);
        Self {
            builtin: Arc::new(builtin),
        }
    }

    pub fn contract(
        &self, address: &Address,
    ) -> Option<&Box<dyn InternalContractTrait>> {
        self.builtin.get(address)
    }
}
