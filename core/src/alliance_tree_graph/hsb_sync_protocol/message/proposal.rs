// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hotstuff_types::proposal_msg::ProposalMsg,
    primitives::TransactionWithSignature,
    sync::{
        message::{Context, Handleable},
        Error,
    },
};

pub type ProposalMsgWithTransactions = ProposalMsg<TransactionWithSignature>;

impl Handleable for ProposalMsgWithTransactions {
    fn handle(self, _ctx: &Context) -> Result<(), Error> { Ok(()) }
}
