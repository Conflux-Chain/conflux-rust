// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod cpu;
pub mod stratum;

use cfxcore::pow::{
    nonce_has_non_zero_high_128_bits, ProofOfWorkProblem, ProofOfWorkSolution,
};
use std::sync::Arc;
use stratum::Stratum;

use crate::{BlockGenerator, SolutionReceiver};

pub(crate) fn has_zero_high_nonce(solution: &ProofOfWorkSolution) -> bool {
    !nonce_has_non_zero_high_128_bits(&solution.nonce)
}

pub trait MineWorker {
    fn receive_problem(&self, problem: ProofOfWorkProblem);
}

pub enum MinerType {
    Stratum,
    Cpu(usize), // Number of CPU workers
}

pub fn spawn(
    bg: Arc<BlockGenerator>, miner_type: MinerType,
) -> (Box<dyn MineWorker>, SolutionReceiver) {
    let (worker, solution_receiver): (Box<dyn MineWorker>, _) = match miner_type
    {
        MinerType::Stratum => {
            let (stratum, receiver) = Stratum::spawn(&bg);
            (Box::new(stratum), receiver)
        }
        MinerType::Cpu(num_workers) => {
            let (worker_manager, receiver) =
                cpu::CpuMinerCoordinator::spawn(bg, num_workers);
            (Box::new(worker_manager), receiver)
        }
    };
    (worker, solution_receiver)
}

#[cfg(test)]
mod tests {
    use super::has_zero_high_nonce;
    use cfx_types::U256;
    use cfxcore::pow::ProofOfWorkSolution;

    #[test]
    fn local_solution_requires_zero_high_nonce() {
        let solution = |nonce| ProofOfWorkSolution { nonce };

        assert!(has_zero_high_nonce(&solution(U256::zero())));
        assert!(has_zero_high_nonce(&solution(
            (U256::one() << 128) - U256::one()
        )));
        assert!(!has_zero_high_nonce(&solution(U256::one() << 128)));
        assert!(!has_zero_high_nonce(&solution(U256::one() << 255)));
    }
}
