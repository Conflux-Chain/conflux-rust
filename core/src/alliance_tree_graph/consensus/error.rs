// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ConsensusError {
    VerifyPivotTimeout,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::ConsensusError::*;
        let msg = match *self {
            VerifyPivotTimeout => format!("Verify pivot block timeout"),
        };

        f.write_fmt(format_args!("Consensus error ({})", msg))
    }
}

impl std::error::Error for ConsensusError {
    fn description(&self) -> &str { "Consensus error" }
}
