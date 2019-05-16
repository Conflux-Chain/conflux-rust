use crate::ConsensusGraph;
use cfx_types::H256;
use parking_lot::Mutex;
use std::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
    thread,
};

enum RunningState {
    Start,
    Stop,
}

pub struct ConsensusExecutor {
    sender: Sender<ExecutionTask>,
    receiver: Option<Receiver<ExecutionTask>>,
    state: Arc<Mutex<RunningState>>,
}

impl ConsensusExecutor {
    pub fn new() -> Self {
        let (sender, receiver) = channel();
        ConsensusExecutor {
            sender,
            receiver: Some(receiver),
            state: Arc::new(Mutex::new(RunningState::Start)),
        }
    }

    pub fn start(&mut self, consensus: Arc<ConsensusGraph>) {
        // It receives blocks hashes from on_new_block and execute them
        let receiver = self.receiver.take().unwrap();
        let state = self.state.clone();
        thread::Builder::new()
            .name("Consensus Execution Worker".into())
            .spawn(move || loop {
                match *state.lock() {
                    RunningState::Stop => break,
                    _ => {}
                }
                match receiver.recv() {
                    Ok(task) => consensus.handle_execution_work(task),
                    Err(_) => break,
                }
            })
            .expect("Cannot fail");
    }

    pub fn wait_for_result(&self, epoch_index: usize) -> (H256, H256) {
        let (sender, receiver) = channel();
        self.sender
            .send(ExecutionTask::GetResult(GetExecutionResultTask {
                epoch_index,
                sender,
            }))
            .expect("Cannot fail");
        receiver.recv().unwrap()
    }

    pub fn enqueue_epoch(
        &self, epoch_index: usize, reward_index: Option<(usize, usize)>,
        on_local_pivot: bool,
    ) -> bool
    {
        self.sender
            .send(ExecutionTask::ExecuteEpoch(EpochExecutionTask {
                epoch_index,
                reward_index,
                on_local_pivot,
            }))
            .is_ok()
    }

    pub fn stop(&self) { *self.state.lock() = RunningState::Stop; }
}

pub enum ExecutionTask {
    ExecuteEpoch(EpochExecutionTask),
    GetResult(GetExecutionResultTask),
}

pub struct EpochExecutionTask {
    pub epoch_index: usize,
    pub reward_index: Option<(usize, usize)>,
    pub on_local_pivot: bool,
}

pub struct GetExecutionResultTask {
    pub epoch_index: usize,
    pub sender: Sender<(H256, H256)>,
}
