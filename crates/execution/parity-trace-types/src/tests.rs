use super::{
    action_types::{Action, Call},
    trace_types::{BlockExecTraces, ExecTrace, TransactionExecTraces},
};
use cfx_vm_types::CallType;
use rlp::*;

#[test]
fn encode_flat_transaction_traces() {
    let ftt = TransactionExecTraces::from(Vec::new());

    let mut s = RlpStream::new_list(2);
    s.append(&ftt);
    assert!(!s.is_finished(), "List shouldn't finished yet");
    s.append(&ftt);
    assert!(s.is_finished(), "List should be finished now");
    s.out();
}

#[test]
fn encode_flat_block_traces() {
    let fbt = BlockExecTraces::from(Vec::new());

    let mut s = RlpStream::new_list(2);
    s.append(&fbt);
    assert!(!s.is_finished(), "List shouldn't finished yet");
    s.append(&fbt);
    assert!(s.is_finished(), "List should be finished now");
    s.out();
}

#[test]
fn test_trace_serialization() {
    // block #51921

    let flat_trace = ExecTrace {
        action: Action::Call(Call {
            space: Default::default(),
            from: "8dda5e016e674683241bf671cced51e7239ea2bc".parse().unwrap(),
            to: "37a5e19cc2d49f244805d5c268c0e6f321965ab9".parse().unwrap(),
            value: "3627e8f712373c0000".parse().unwrap(),
            gas: 0x03e8.into(),
            input: vec![],
            call_type: CallType::Call,
        }),
        valid: true,
    };

    let flat_trace1 = ExecTrace {
        action: Action::Call(Call {
            space: Default::default(),
            from: "3d0768da09ce77d25e2d998e6a7b6ed4b9116c2d".parse().unwrap(),
            to: "412fda7643b37d436cb40628f6dbbb80a07267ed".parse().unwrap(),
            value: 0.into(),
            gas: 0x010c78.into(),
            input: vec![0x41, 0xc0, 0xe1, 0xb5],
            call_type: CallType::Call,
        }),
        valid: true,
    };

    let block_traces = BlockExecTraces(vec![
        TransactionExecTraces(vec![flat_trace]),
        TransactionExecTraces(vec![flat_trace1]),
    ]);

    let encoded = ::rlp::encode(&block_traces);
    let decoded = ::rlp::decode(&encoded).expect("error decoding block traces");
    assert_eq!(block_traces, decoded);
}
