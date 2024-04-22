use super::Builtin;
use cfx_bytes::BytesRef;
use cfx_statedb::Result as DbResult;
use cfx_vm_interpreter::Finalize;
use cfx_vm_types::{ActionParams, Error as VmError, GasLeft, ReturnData};

use crate::{
    context::Context,
    stack::{Executable, ExecutableOutcome},
};

pub struct BuiltinExec<'a> {
    pub builtin: &'a Builtin,
    pub params: ActionParams,
}

impl<'a> Executable for BuiltinExec<'a> {
    fn execute(
        self: Box<Self>, context: Context,
    ) -> DbResult<ExecutableOutcome> {
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
        Ok(ExecutableOutcome::Return(output.finalize(context)))
    }
}
