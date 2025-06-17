mod state;

use crate::{BlockGenerator, MineWorker, SolutionReceiver};
use cfxcore::pow::ProofOfWorkProblem;
use log::{debug, trace, warn};
use std::{
    ops::Deref,
    thread,
    time::{self, Duration},
};

use state::MineState;

// A maximum interval to update the mining block
const BLOCK_FORCE_UPDATE_INTERVAL: Duration = Duration::from_secs(10);
// Avoid busy loop: sleep for 30ms if the current loop iteration does nothing
const BLOCKGEN_LOOP_SLEEP_DURATION: Duration = time::Duration::from_millis(30);

pub(crate) struct MiningSession<'a> {
    bg: &'a BlockGenerator,
    miner: &'a dyn MineWorker,
    solution_rx: SolutionReceiver,
    state: MineState,
}

impl<'a> MiningSession<'a> {
    pub fn new(
        bg: &'a BlockGenerator, miner: &'a dyn MineWorker,
        solution_rx: SolutionReceiver,
    ) -> Self {
        let state =
            MineState::with_capacity(bg.pow_config.pow_problem_window_size);

        MiningSession {
            bg,
            miner,
            solution_rx,
            state,
        }
    }

    pub fn run(mut self) {
        while self.bg.is_running() {
            // TODO: #transations TBD
            if !self.should_mine() {
                thread::sleep(BLOCKGEN_LOOP_SLEEP_DURATION);
                continue;
            }

            if self.is_mining_block_outdated() {
                // Compute new mining task and send to workers
                self.update_mining_task();
                // Pull the mining solution
                self.process_pending_solutions();
            }
        }
    }

    fn should_mine(&self) -> bool {
        self.pow_config.test_mode || !self.sync.catch_up_mode()
    }

    /// Check if we need to mine on a new block
    fn is_mining_block_outdated(&self) -> bool {
        // TODO: update the logic here.

        let Some(block) = self.state.mining_block() else {
            return true;
        };

        // 1st Check: if the parent block changed
        let best_block_hash = self.consensus.best_block_hash();
        if best_block_hash != *block.block_header.parent_hash() {
            return true;
        }

        // 2nd Check: if the last block is too old, we will generate a new
        // block. Checking transaction updates and referees might be
        // costly and the trade-off is unclear here. It is simple to
        // just enforce a time here.

        self.state.last_assemble_elapsed() > BLOCK_FORCE_UPDATE_INTERVAL
    }

    fn update_mining_task(&mut self) {
        let next_mining_block = self.assembler.assemble_new_mining_block(None);
        self.state.touch_last_assemble();

        let problem = ProofOfWorkProblem::from_block_header(
            &next_mining_block.block_header,
        );

        self.state.update_job(next_mining_block, problem);
        self.send_problem(problem);
    }

    /// Pull mining solution from the workers, returns whether a valid solution
    /// is found
    fn process_pending_solutions(&mut self) {
        while let Ok(solution) = self.solution_rx.try_recv() {
            debug!("new solution: {:?}", solution);

            if let Some(mut mined_block) =
                self.state.validate_and_claim_solution(&solution, |p, s| {
                    self.bg.pow.validate(p, s)
                })
            {
                mined_block.block_header.set_nonce(solution.nonce);
                mined_block.block_header.compute_hash();

                self.on_mined_block(mined_block);
                return;
            } else {
                warn!(
                    "Received invalid solution from miner: nonce = {}!",
                    &solution.nonce
                );
            }
        }

        // The solution channel is empty, or all pending solutions were invalid.
        // We should ensure if the miner has current job.
        self.ensure_miner_has_current_work();
        // Avoid busy-waiting
        thread::sleep(BLOCKGEN_LOOP_SLEEP_DURATION);
    }

    /// We will send out heartbeat because newcomers or
    /// disconnected people may lose the previous message
    fn ensure_miner_has_current_work(&mut self) {
        if !self.pow_config.use_stratum() {
            return;
        }

        if let Some(problem) = self.state.check_for_renotification() {
            self.send_problem(problem);
        }
    }

    fn send_problem(&mut self, problem: ProofOfWorkProblem) {
        self.miner.receive_problem(problem);

        trace!("send problem: {:?}", problem);
        self.state.touch_last_notify();
    }
}

impl<'a> Deref for MiningSession<'a> {
    type Target = BlockGenerator;

    fn deref(&self) -> &Self::Target { &*self.bg }
}
