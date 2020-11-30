// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::SolidityFunctionTrait;
use crate::{
    state::{StateGeneric, Substate},
    vm::{self, ActionParams, CallType, GasLeft, ReturnData, Spec},
};
use cfx_storage::StorageStateTrait;
use cfx_types::U256;
use solidity_abi::{ABIDecodable, ABIEncodable};

/// The standard implementation of the solidity function trait. The developer of
/// new functions should implement the following traits.
///
/// The `InterfaceTrait` is implemented when constructing a new struct with
/// macro `make_solidity_function`.
///
/// The `PreExecCheckTrait` and `UpfrontPaymentTrait` trait can be implemented
/// by macro `set_default_config`. By default, the contract with be set non
/// payable and forbid static. Sometimes we need to implement
/// `UpfrontPaymentTrait` manually if the gas required is not a constant value.
///
/// You always needs to implement `ExecutionTrait`, which is the core of the
/// function execution.
impl<T, S: StorageStateTrait> SolidityFunctionTrait<S> for T
where T: InterfaceTrait
        + PreExecCheckTrait
        + UpfrontPaymentTrait<S>
        + ExecutionTrait<S>
{
    fn execute(
        &self, input: &[u8], params: &ActionParams, spec: &Spec,
        state: &mut StateGeneric<S>, substate: &mut Substate,
    ) -> vm::Result<GasLeft>
    {
        self.pre_execution_check(params, substate)?;
        let solidity_params = <T::Input as ABIDecodable>::abi_decode(&input)?;

        let cost =
            self.upfront_gas_payment(&solidity_params, params, spec, state);
        if cost > params.gas {
            return Err(vm::Error::OutOfGas);
        }

        self.execute_inner(solidity_params, params, spec, state, substate)
            .and_then(|output| {
                let output = output.abi_encode();
                let length = output.len();
                let return_cost = (length + 31) / 32 * spec.memory_gas;
                if params.gas < cost + return_cost {
                    Err(vm::Error::OutOfGas)
                } else {
                    Ok(GasLeft::NeedsReturn {
                        gas_left: params.gas - cost - return_cost,
                        data: ReturnData::new(output, 0, length),
                        apply_state: true,
                    })
                }
            })
    }

    fn name(&self) -> &'static str { return Self::NAME_AND_PARAMS; }
}

pub trait InterfaceTrait {
    type Input: ABIDecodable;
    type Output: ABIEncodable;
    const NAME_AND_PARAMS: &'static str;
}

pub trait PreExecCheckTrait: Send + Sync {
    fn pre_execution_check(
        &self, params: &ActionParams, substate: &Substate,
    ) -> vm::Result<()>;
}

pub trait ExecutionTrait<S: StorageStateTrait>:
    Send + Sync + InterfaceTrait
{
    fn execute_inner(
        &self, input: Self::Input, params: &ActionParams, spec: &Spec,
        state: &mut StateGeneric<S>, substate: &mut Substate,
    ) -> vm::Result<<Self as InterfaceTrait>::Output>;
}

pub trait UpfrontPaymentTrait<S: StorageStateTrait>:
    Send + Sync + InterfaceTrait
{
    fn upfront_gas_payment(
        &self, input: &Self::Input, params: &ActionParams, spec: &Spec,
        state: &StateGeneric<S>,
    ) -> U256;
}

pub trait PreExecCheckConfTrait: Send + Sync {
    /// Whether such internal function is payable.
    const PAYABLE: bool;
    /// Whether such internal function has write operation.
    const HAS_WRITE_OP: bool;
}

impl<T: PreExecCheckConfTrait> PreExecCheckTrait for T {
    fn pre_execution_check(
        &self, params: &ActionParams, substate: &Substate,
    ) -> vm::Result<()> {
        if !Self::PAYABLE && !params.value.value().is_zero() {
            return Err(vm::Error::InternalContract(
                "should not transfer balance to Staking contract",
            ));
        }

        if Self::HAS_WRITE_OP
            && (substate.contracts_in_callstack.borrow().in_reentrancy()
                || params.call_type == CallType::StaticCall)
        {
            return Err(vm::Error::MutableCallInStaticContext);
        }

        Ok(())
    }
}

#[macro_export]
/// Make a solidity interface function, it requires three parameters
/// 1. The type of input parameters.
/// 2. The string to compute interface signature.
/// 3. The type of output parameters.
///
/// For example, in order to make a function with interface
/// get_whitelist(address user, address contract) public returns bool, you
/// should use
/// ```
/// use cfxcore::make_solidity_function;
/// use cfx_types::{Address,U256};
/// use cfxcore::executive::function::InterfaceTrait;
///
/// make_solidity_function!{
///     struct WhateverStructName((Address, Address), "get_whitelist(address,address)", bool);
/// }
/// ```
/// If the function has no return value, the third parameter can be omitted.
macro_rules! make_solidity_function {
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($input:ty, $interface:expr ); ) => {
        $crate::make_solidity_function! {
            $(#[$attr])* $visibility struct $name ($input, $interface, () );
        }
    };
    ( $(#[$attr:meta])* $visibility:vis struct $name:ident ($input:ty, $interface:expr, $output:ty ); ) => {
        $(#[$attr])*
        #[derive(Copy, Clone)]
        $visibility struct $name<S> {
            phantom: std::marker::PhantomData<S>,
        }

        impl<S> $name<S> {
            pub fn instance() -> Self {
                Self {
                    phantom: Default::default(),
                }
            }
        }

        impl<S> InterfaceTrait for $name<S> {
            type Input = $input;
            type Output = $output;
            const NAME_AND_PARAMS: &'static str = $interface;
        }
    };
}

#[macro_export]
macro_rules! impl_function_type {
    ( $name:ident, "non_payable_write" $(, gas: $gas:expr)? ) => {
        $crate::impl_function_type!(@inner, $name, false, true $(, $gas)?);
    };
    ( $name:ident, "payable_write" $(, gas: $gas:expr)? ) => {
        $crate::impl_function_type!(@inner, $name, true, true $(, $gas)?);
    };
    ( $name:ident, "query" $(, gas: $gas:expr)? ) => {
        $crate::impl_function_type!(@inner, $name, false, false $(, $gas)?);
    };
    ( @inner, $name:ident, $payable:expr, $has_write_op:expr $(, $gas:expr)? ) => {
        impl<S: Send + Sync> PreExecCheckConfTrait for $name<S> {
            const PAYABLE: bool = $payable;
            const HAS_WRITE_OP: bool = $has_write_op;
        }
        $(
            impl<S: cfx_storage::StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S> for $name<S> {
                fn upfront_gas_payment(
                    &self, _input: &Self::Input, _params: &ActionParams, _spec: &Spec, _state: &StateGeneric<S>,
                ) -> U256 {
                    U256::from($gas)
                }
            }
        )?
    };
    ( $name:ident, "query_with_default_gas" ) => {
        impl<S: Send + Sync> PreExecCheckConfTrait for $name<S> {
            const PAYABLE: bool = false ;
            const HAS_WRITE_OP: bool = false;
        }

        impl<S: cfx_storage::StorageStateTrait + Send + Sync> UpfrontPaymentTrait<S> for $name<S> {
            fn upfront_gas_payment(
                &self, _input: &Self::Input, _params: &ActionParams, spec: &Spec, _state: &StateGeneric<S>,
            ) -> U256 {
                U256::from(spec.balance_gas)
            }
        }
    };
}
