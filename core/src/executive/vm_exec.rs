use crate::{
    builtin::Builtin,
    evm::{CallType, Context, GasLeft, ReturnData},
    executive::InternalContractTrait,
    trace::{trace::ExecTrace, Tracer},
    vm::{ActionParams, Error as VmError, Exec, ExecTrapResult, TrapResult},
};
use cfx_bytes::BytesRef;
use cfx_types::U256;

pub struct NoopExec {
    pub gas: U256,
}

impl Exec for NoopExec {
    fn exec(
        self: Box<Self>, _: &mut dyn Context,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> ExecTrapResult<GasLeft>
    {
        TrapResult::Return(Ok(GasLeft::Known(self.gas)))
    }
}
pub struct BuiltinExec<'a> {
    pub builtin: &'a Builtin,
    pub params: ActionParams,
}

impl<'a> Exec for BuiltinExec<'a> {
    fn exec(
        self: Box<Self>, _: &mut dyn Context,
        _: &mut dyn Tracer<Output = ExecTrace>,
    ) -> ExecTrapResult<GasLeft>
    {
        let default = [];
        let data = if let Some(ref d) = self.params.data {
            d as &[u8]
        } else {
            &default as &[u8]
        };

        let cost = self.builtin.cost(data);
        let output = if cost <= self.params.gas {
            let mut builtin_out_buffer = Vec::new();
            let result = {
                let mut builtin_output =
                    BytesRef::Flexible(&mut builtin_out_buffer);
                self.builtin.execute(data, &mut builtin_output)
            };
            match result {
                Ok(_) => {
                    let out_len = builtin_out_buffer.len();
                    Ok(GasLeft::NeedsReturn {
                        gas_left: self.params.gas - cost,
                        data: ReturnData::new(builtin_out_buffer, 0, out_len),
                        apply_state: true,
                    })
                }
                Err(e) => Err(e.into()),
            }
        } else {
            Err(VmError::OutOfGas)
        };
        TrapResult::Return(output)
    }
}

pub struct InternalContractExec<'a> {
    pub internal: &'a Box<dyn InternalContractTrait>,
    pub params: ActionParams,
}

impl<'a> Exec for InternalContractExec<'a> {
    fn exec(
        self: Box<Self>, context: &mut dyn Context,
        tracer: &mut dyn Tracer<Output = ExecTrace>,
    ) -> ExecTrapResult<GasLeft>
    {
        let result = if self.params.call_type != CallType::Call
            && self.params.call_type != CallType::StaticCall
        {
            Err(VmError::InternalContract("Incorrect call type."))
        } else {
            let mut context = context.internal_ref();
            self.internal.execute(&self.params, &mut context, tracer)
        };
        debug!("Internal Call Result: {:?}", result);
        TrapResult::Return(result)
    }
}
