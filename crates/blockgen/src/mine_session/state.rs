use cfxcore::pow::{ProofOfWorkProblem, ProofOfWorkSolution};
use primitives::Block;
use std::{
    collections::VecDeque,
    time::{self, Instant},
};
use time::Duration;

#[derive(Clone, Debug)]
pub struct MineJob {
    block: Block,
    problem: ProofOfWorkProblem,
}

pub struct MineState {
    job_history: VecDeque<MineJob>,
    mining_job: Option<MineJob>,
    last_notify_at: Instant,
    last_assemble_at: Instant,
    history_capacity: usize,
}

impl MineState {
    /// Creates a new job cache with the specified history capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        MineState {
            job_history: VecDeque::with_capacity(capacity),
            mining_job: None,
            last_notify_at: Instant::now(),
            last_assemble_at: Instant::now(),
            history_capacity: capacity,
        }
    }

    pub fn mining_block(&self) -> Option<&Block> {
        self.mining_job.as_ref().map(|job| &job.block)
    }

    pub fn last_assemble_elapsed(&self) -> Duration {
        self.last_assemble_at.elapsed()
    }

    pub fn touch_last_assemble(&mut self) {
        self.last_assemble_at = Instant::now();
    }

    pub fn touch_last_notify(&mut self) {
        self.last_notify_at = Instant::now();
    }

    /// Sets a new mining job as the current one and adds it to the history.
    ///
    /// This should be called whenever a new block template is created.
    pub fn update_job(&mut self, block: Block, problem: ProofOfWorkProblem) {
        if self.job_history.len() == self.history_capacity {
            self.job_history.pop_front();
        }
        let new_job = MineJob { block, problem };
        self.job_history.push_back(new_job.clone());
        self.mining_job = Some(new_job);
        self.last_assemble_at = Instant::now();
    }

    /// Validates a proof-of-work solution against the job history.
    ///
    /// If the solution is valid for any recent job, this method returns the
    /// corresponding block and clears the current job.
    pub fn validate_and_claim_solution(
        &mut self, solution: &ProofOfWorkSolution,
        validate: impl Fn(&ProofOfWorkProblem, &ProofOfWorkSolution) -> bool,
    ) -> Option<Block> {
        let result = self
            .job_history
            .iter()
            .find(|job| validate(&job.problem, solution))
            .map(|job| job.block.clone());

        if result.is_some() {
            // Clear current mining info after a solution is found
            self.mining_job = None;
        }
        result
    }

    /// Checks if it's time to re-notify miners of the current proof-of-work
    /// problem.
    ///
    /// This is a heartbeat mechanism to ensure that new or temporarily
    /// disconnected miners receive the current job.
    pub fn check_for_renotification(&self) -> Option<ProofOfWorkProblem> {
        let Some(MineJob { problem, .. }) = self.mining_job.as_ref() else {
            return None;
        };
        if self.last_notify_at.elapsed() > Duration::from_secs(60) {
            Some(problem.clone())
        } else {
            None
        }
    }
}
