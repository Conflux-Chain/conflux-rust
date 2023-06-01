// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod components;
mod contracts;
mod impls;
mod utils;

pub use self::{
    components::{
        InterfaceTrait, InternalContractMap, InternalContractTrait,
        InternalRefContext,
    },
    contracts::cross_space::{is_call_create_sig, is_withdraw_sig},
    impls::{
        admin::suicide,
        cross_space::{
            build_bloom_and_recover_phantom, evm_map, PhantomTransaction,
        },
        params_control::{
            get_settled_param_vote_count, get_settled_pos_staking_for_votes,
            settle_current_votes, storage_point_prop, AllParamsVoteCount,
            ParamVoteCount,
        },
        pos::{
            decode_register_info, entries as pos_internal_entries, IndexStatus,
        },
    },
};
