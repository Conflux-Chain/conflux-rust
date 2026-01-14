use cfx_types::U256;
use cfxcore::pow::{PowComputer, ProofOfWorkProblem, ProofOfWorkSolution};
use log::{trace, warn};
use std::{
    sync::{
        mpsc::{self, TryRecvError},
        Arc,
    },
    thread,
    time::Duration,
};

/// This determined the frequency of checking a new PoW problem.
/// And the current mining speed in the Rust implementation is about 2 ms per
/// nonce.
const NONCES_PER_ATTEMPT: u64 = 20;
const FETCH_PROBLEM_INTERVAL: Duration = Duration::from_millis(100);

use crate::{BlockGenerator, SolutionReceiver};

use super::MineWorker;

pub struct CpuMinerCoordinator {
    problem_txs: Vec<mpsc::Sender<ProofOfWorkProblem>>,
}

impl CpuMinerCoordinator {
    /// Creates a new worker manager.
    pub fn spawn(
        bg: Arc<BlockGenerator>, num_worker: usize,
    ) -> (Self, SolutionReceiver) {
        let (solution_tx, solution_rx) = mpsc::channel();
        let mut problem_txs = vec![];
        for _ in 0..num_worker {
            let (problem_tx, problem_rx) = mpsc::channel();
            CpuMiner::spawn(bg.clone(), solution_tx.clone(), problem_rx);
            problem_txs.push(problem_tx);
        }

        (Self { problem_txs }, solution_rx)
    }
}

impl MineWorker for CpuMinerCoordinator {
    /// Receives a new problem and sends it to all workers.
    fn receive_problem(&self, problem: ProofOfWorkProblem) {
        for sender in &self.problem_txs {
            sender
                .send(problem.clone())
                .expect("Failed to send the PoW problem.");
        }
    }
}

pub struct CpuMiner {
    bg: Arc<BlockGenerator>,
    solution_tx: mpsc::Sender<ProofOfWorkSolution>,
    problem_rx: mpsc::Receiver<ProofOfWorkProblem>,
}

impl CpuMiner {
    pub fn spawn(
        bg: Arc<BlockGenerator>,
        solution_tx: mpsc::Sender<ProofOfWorkSolution>,
        problem_rx: mpsc::Receiver<ProofOfWorkProblem>,
    ) {
        let worker = CpuMiner {
            bg,
            solution_tx,
            problem_rx,
        };
        thread::Builder::new()
            .name("blockgen".into())
            .spawn(move || worker.run())
            .expect("only one blockgen thread, so it should not fail");
    }

    pub fn run(self) {
        use TryRecvError::*;

        let bg = &self.bg;
        let bg_pow = PowComputer::new(bg.pow_config.use_octopus());
        let mut maybe_problem = None;

        while bg.is_running() {
            match self.try_fetch_latest_problem() {
                Err(Disconnected) => return,
                Err(Empty) => {
                    if maybe_problem.is_none() {
                        thread::sleep(FETCH_PROBLEM_INTERVAL);
                        continue;
                    }
                }
                Ok(new_problem) => maybe_problem = Some(new_problem),
            };

            // If there is a problem to be solved
            let problem = maybe_problem.expect("already set");
            trace!("problem is {:?}", problem);
            let boundary = problem.boundary;
            let block_hash = problem.block_hash;
            let block_height = problem.block_height;

            let start_nonce: u128 = rand::random();
            let maybe_solution = (0..NONCES_PER_ATTEMPT)
                .filter_map(|offset| {
                    let nonce: U256 =
                        start_nonce.overflowing_add(offset as u128).0.into();
                    let hash =
                        bg_pow.compute(&nonce, &block_hash, block_height);
                    ProofOfWorkProblem::validate_hash_against_boundary(
                        &hash, &nonce, &boundary,
                    )
                    .then_some(nonce)
                })
                .next();

            if let Some(nonce) = maybe_solution {
                let send_res =
                    self.solution_tx.send(ProofOfWorkSolution { nonce });
                if let Err(e) = send_res {
                    warn!("Proof of work send error {}", e);
                } else {
                    maybe_problem = None;
                }
            }
        }
    }

    /// Drain the channel to check the latest problem
    fn try_fetch_latest_problem(
        &self,
    ) -> Result<ProofOfWorkProblem, TryRecvError> {
        use TryRecvError::*;

        let mut problem: Option<ProofOfWorkProblem> = None;
        loop {
            let maybe_new_problem = self.problem_rx.try_recv();
            trace!("new problem: {:?}", problem);
            match maybe_new_problem {
                Err(Empty) => break,
                Err(Disconnected) => {
                    return Err(Disconnected);
                }
                Ok(new_problem) => {
                    problem = Some(new_problem);
                }
            }
        }
        if let Some(p) = problem {
            Ok(p)
        } else {
            Err(Empty)
        }
    }
}
