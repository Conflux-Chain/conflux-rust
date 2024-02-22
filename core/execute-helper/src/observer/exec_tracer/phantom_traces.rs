// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    action_types::{
        Action, Call, CallResult, Create, CreateResult, InternalTransferAction,
        Outcome,
    },
    trace_types::{ExecTrace, TransactionExecTraces},
};

use cfx_executor::{
    executive_observer::AddressPocket,
    internal_contract::{is_call_create_sig, is_withdraw_sig},
};
use cfx_parameters::internal_contract_addresses::CROSS_SPACE_CONTRACT_ADDRESS;
use cfx_types::{Address, AddressWithSpace, Space, H256, U256};
use cfx_vm_types::CallType;
use solidity_abi::ABIEncodable;

pub fn recover_phantom_trace_for_withdraw(
    mut tx_traces: impl Iterator<Item = ExecTrace>,
) -> Result<Vec<TransactionExecTraces>, String> {
    let trace = match tx_traces.next() {
        Some(t) => t,
        None => {
            error!("Unable to recover phantom trace: no more traces (expected withdraw)");
            return Err("Unable to recover phantom trace: no more traces (expected withdraw)".into());
        }
    };

    match trace.action {
        Action::InternalTransferAction(InternalTransferAction {
            from:
                AddressPocket::Balance(AddressWithSpace {
                    address: from,
                    space: Space::Ethereum,
                }),
            to:
                AddressPocket::Balance(AddressWithSpace {
                    address: _,
                    space: Space::Native,
                }),
            value,
        }) => {
            return Ok(vec![TransactionExecTraces(vec![
                ExecTrace {
                    action: Action::Call(Call {
                        space: Space::Ethereum,
                        from,
                        to: Address::zero(),
                        value,
                        gas: 0.into(),
                        input: Default::default(),
                        call_type: CallType::Call,
                    }),
                    valid: true,
                },
                ExecTrace {
                    action: Action::CallResult(CallResult {
                        outcome: Outcome::Success,
                        gas_left: 0.into(),
                        return_data: Default::default(),
                    }),
                    valid: true,
                },
            ])]);
        }

        _ => {
            error!("Unable to recover phantom trace: unexpected trace type while processing withdraw: {:?}", trace);
            return Err("Unable to recover phantom trace: unexpected trace type while processing withdraw".into());
        }
    }
}

pub fn recover_phantom_trace_for_call(
    tx_traces: &mut impl Iterator<Item = ExecTrace>, original_tx_hash: H256,
    cross_space_nonce: u32,
) -> Result<Vec<TransactionExecTraces>, String> {
    let mut traces = vec![];

    let trace = match tx_traces.next() {
        Some(t) => t,
        None => {
            error!("Unable to recover phantom trace: no more traces (expected balance transfer) hash={:?}, nonce={:?}", original_tx_hash, cross_space_nonce);
            return Err("Unable to recover phantom trace: no more traces (expected balance transfer)".into());
        }
    };

    match trace.action {
        Action::InternalTransferAction(InternalTransferAction {
            from: _,
            to:
                AddressPocket::Balance(AddressWithSpace {
                    address,
                    space: Space::Ethereum,
                }),
            value,
        }) => {
            let input =
                (original_tx_hash, U256::from(cross_space_nonce)).abi_encode();

            traces.push(TransactionExecTraces(vec![
                ExecTrace {
                    action: Action::Call(Call {
                        space: Space::Ethereum,
                        from: Address::zero(),
                        to: address,
                        value,
                        gas: 0.into(),
                        input,
                        call_type: CallType::Call,
                    }),
                    valid: true,
                },
                ExecTrace {
                    action: Action::CallResult(CallResult {
                        outcome: Outcome::Success,
                        gas_left: 0.into(),
                        return_data: Default::default(),
                    }),
                    valid: true,
                },
            ]));
        }

        _ => {
            error!("Unable to recover phantom trace: unexpected trace type while processing call (hash={:?}, nonce={:?}): {:?}", original_tx_hash, cross_space_nonce, trace);
            return Err("Unable to recover phantom trace: unexpected trace type while processing call".into());
        }
    }

    let mut stack_depth = 0;
    let mut phantom_traces = vec![];

    loop {
        let mut trace = match tx_traces.next() {
            Some(t) => t,
            None => {
                error!("Unable to recover phantom trace: no more traces (expected eSpace trace entry) hash={:?}, nonce={:?}", original_tx_hash, cross_space_nonce);
                return Err("Unable to recover phantom trace: no more traces (expected eSpace trace entry)".into());
            }
        };

        // phantom traces have 0 gas
        match trace.action {
            Action::Call(Call { ref mut gas, .. }) => {
                *gas = 0.into();
            }
            Action::Create(Create { ref mut gas, .. }) => {
                *gas = 0.into();
            }
            Action::CallResult(CallResult {
                ref mut gas_left, ..
            }) => {
                *gas_left = 0.into();
            }
            Action::CreateResult(CreateResult {
                ref mut gas_left, ..
            }) => {
                *gas_left = 0.into();
            }
            Action::InternalTransferAction(InternalTransferAction {
                ..
            }) => {}
        }

        phantom_traces.push(trace);

        match phantom_traces.last().as_ref().unwrap().action {
            Action::Call(_) | Action::Create(_) => {
                stack_depth += 1;
            }
            Action::CallResult(_) | Action::CreateResult(_) => {
                stack_depth -= 1;

                if stack_depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }

    traces.push(TransactionExecTraces(phantom_traces));
    Ok(traces)
}

pub fn recover_phantom_traces(
    tx_traces: TransactionExecTraces, original_tx_hash: H256,
) -> Result<Vec<TransactionExecTraces>, String> {
    let mut traces: Vec<TransactionExecTraces> = vec![];
    let mut traces_iter = tx_traces.0.into_iter();
    let mut cross_space_nonce = 0u32;

    loop {
        let trace = match traces_iter.next() {
            Some(t) => t,
            None => break,
        };

        match trace.action {
            Action::Call(Call {
                space: Space::Native,
                to,
                call_type: CallType::Call,
                input,
                ..
            }) if to == CROSS_SPACE_CONTRACT_ADDRESS
                && trace.valid
                && is_call_create_sig(&input[0..4]) =>
            {
                let phantom_traces = recover_phantom_trace_for_call(
                    &mut traces_iter,
                    original_tx_hash,
                    cross_space_nonce,
                )?;

                traces.extend(phantom_traces);
                cross_space_nonce += 1;
            }
            Action::Call(Call {
                space: Space::Native,
                to,
                call_type: CallType::Call,
                input,
                ..
            }) if to == CROSS_SPACE_CONTRACT_ADDRESS
                && trace.valid
                && is_withdraw_sig(&input[0..4]) =>
            {
                let phantom_traces =
                    recover_phantom_trace_for_withdraw(&mut traces_iter)?;

                traces.extend(phantom_traces);
            }
            _ => {}
        }
    }

    Ok(traces)
}
