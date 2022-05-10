// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_statedb::Result as DbResult;
use cfx_types::U256;
use solidity_abi::{ABIDecodable, ABIEncodable};

use crate::{
    observer::VmObserve,
    state::CallStackInfo,
    vm::{
        self, ActionParams, CallType, ExecTrapResult, GasLeft, ReturnData,
        Spec, TrapResult,
    },
};

use super::{InternalRefContext, IsActive};

/// Native implementation of a solidity-interface function.
pub trait SolidityFunctionTrait: Send + Sync + IsActive {
    fn execute(
        &self, input: &[u8], params: &ActionParams,
        context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    ) -> ExecTrapResult<GasLeft>;

    /// The string for function sig
    fn name(&self) -> &'static str;

    /// The function sig for this function
    fn function_sig(&self) -> [u8; 4];
}

pub trait SolidityFunctionConfigTrait:
    InterfaceTrait + PreExecCheckTrait + UpfrontPaymentTrait
{
}

impl<T> SolidityFunctionConfigTrait for T where T: InterfaceTrait + PreExecCheckTrait + UpfrontPaymentTrait
{}

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
impl<T: SolidityFunctionConfigTrait + ExecutionTrait + IsActive>
    SolidityFunctionTrait for T
{
    fn execute(
        &self, input: &[u8], params: &ActionParams,
        context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    ) -> ExecTrapResult<GasLeft>
    {
        let (solidity_params, cost) =
            match preprocessing(self, input, params, context) {
                Ok(res) => res,
                Err(err) => {
                    return TrapResult::Return(Err(err));
                }
            };

        let gas_left = params.gas - cost;

        match ExecutionTrait::execute_inner(
            self,
            solidity_params,
            params,
            gas_left,
            context,
            tracer,
        ) {
            TrapResult::Return(output) => {
                let vm_result = output.and_then(|output| {
                    let output = output.abi_encode();
                    let length = output.len();
                    let return_cost = U256::from(
                        (length + 31) / 32 * context.spec.memory_gas,
                    );
                    if gas_left < return_cost {
                        Err(vm::Error::OutOfGas)
                    } else {
                        Ok(GasLeft::NeedsReturn {
                            gas_left: gas_left - return_cost,
                            data: ReturnData::new(output, 0, length),
                            apply_state: true,
                        })
                    }
                });
                TrapResult::Return(vm_result)
            }
            TrapResult::SubCallCreate(trap_error) => {
                TrapResult::SubCallCreate(trap_error)
            }
        }
    }

    fn name(&self) -> &'static str { return Self::NAME_AND_PARAMS; }

    fn function_sig(&self) -> [u8; 4] { return Self::FUNC_SIG; }
}

fn preprocessing<T: SolidityFunctionConfigTrait>(
    sol_fn: &T, input: &[u8], params: &ActionParams,
    context: &InternalRefContext,
) -> vm::Result<(T::Input, U256)>
{
    sol_fn.pre_execution_check(params, context.callstack, context.spec)?;
    let solidity_params = <T::Input as ABIDecodable>::abi_decode(&input)?;
    let cost = sol_fn.upfront_gas_payment(&solidity_params, params, context)?;
    if cost > params.gas {
        return Err(vm::Error::OutOfGas);
    }
    Ok((solidity_params, cost))
}

pub trait InterfaceTrait {
    type Input: ABIDecodable;
    type Output: ABIEncodable;
    const NAME_AND_PARAMS: &'static str;
    const FUNC_SIG: [u8; 4];
}

pub trait PreExecCheckTrait: Send + Sync {
    fn pre_execution_check(
        &self, params: &ActionParams, call_stack: &CallStackInfo,
        context: &Spec,
    ) -> vm::Result<()>;
}

pub trait ExecutionTrait: Send + Sync + InterfaceTrait {
    fn execute_inner(
        &self, input: Self::Input, params: &ActionParams, gas_left: U256,
        context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    ) -> ExecTrapResult<<Self as InterfaceTrait>::Output>;
}

/// The Execution trait without sub-call and sub-create.
pub trait SimpleExecutionTrait: Send + Sync + InterfaceTrait {
    fn execute_inner(
        &self, input: Self::Input, params: &ActionParams,
        context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    ) -> vm::Result<<Self as InterfaceTrait>::Output>;
}

impl<T> ExecutionTrait for T
where T: SimpleExecutionTrait
{
    fn execute_inner(
        &self, input: Self::Input, params: &ActionParams, _gas_left: U256,
        context: &mut InternalRefContext, tracer: &mut dyn VmObserve,
    ) -> ExecTrapResult<<Self as InterfaceTrait>::Output>
    {
        let result = SimpleExecutionTrait::execute_inner(
            self, input, params, context, tracer,
        );
        TrapResult::Return(result)
    }
}

pub trait UpfrontPaymentTrait: Send + Sync + InterfaceTrait {
    fn upfront_gas_payment(
        &self, input: &Self::Input, params: &ActionParams,
        context: &InternalRefContext,
    ) -> DbResult<U256>;
}

pub trait PreExecCheckConfTrait: Send + Sync {
    /// Whether such internal function is payable.
    const PAYABLE: bool;
    /// Whether such internal function has write operation.
    const HAS_WRITE_OP: bool;
}

impl<T: PreExecCheckConfTrait> PreExecCheckTrait for T {
    fn pre_execution_check(
        &self, params: &ActionParams, call_stack: &CallStackInfo, spec: &Spec,
    ) -> vm::Result<()> {
        if !Self::PAYABLE && !params.value.value().is_zero() {
            return Err(vm::Error::InternalContract(
                "should not transfer balance to Staking contract".into(),
            ));
        }

        if Self::HAS_WRITE_OP
            && (call_stack.in_reentrancy(spec)
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
/// use cfxcore::executive::internal_contract::InterfaceTrait;
/// use sha3_macro::keccak;
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
        $visibility struct $name {
        }

        impl $name {
            pub fn instance() -> Self {
                Self {}
            }
        }

        impl InterfaceTrait for $name {
            type Input = $input;
            type Output = $output;
            const NAME_AND_PARAMS: &'static str = $interface;
            const FUNC_SIG: [u8; 4] = {
                let x = keccak!($interface);
                [x[0],x[1],x[2],x[3]]
            };
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
        impl PreExecCheckConfTrait for $name {
            const PAYABLE: bool = $payable;
            const HAS_WRITE_OP: bool = $has_write_op;
        }
        $(
            impl UpfrontPaymentTrait for $name {
                fn upfront_gas_payment(
                    &self, _input: &Self::Input, _params: &ActionParams, context: &InternalRefContext,
                ) -> DbResult<U256> {
                    Ok(U256::from($gas(context.spec)))
                }
            }
        )?
    };
    ( $name:ident, "query_with_default_gas" ) => {
        impl PreExecCheckConfTrait for $name {
            const PAYABLE: bool = false ;
            const HAS_WRITE_OP: bool = false;
        }

        impl UpfrontPaymentTrait for $name {
            fn upfront_gas_payment(
                &self, _input: &Self::Input, _params: &ActionParams, context: &InternalRefContext,
            ) -> DbResult<U256> {
                Ok(U256::from(context.spec.balance_gas))
            }
        }
    };
}
