// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod components;
mod contracts;
mod impls;
mod utils;

pub use self::{
    components::{
        InterfaceTrait, InternalContractExec, InternalContractMap,
        InternalContractTrait, InternalRefContext, SolidityEventTrait,
    },
    contracts::{
        cross_space::{
            events as cross_space_events, is_call_create_sig, is_withdraw_sig,
        },
        initialize_internal_contract_accounts,
    },
    impls::{
        admin::suicide,
        context::{block_hash_slot, epoch_hash_slot},
        cross_space::Resume,
        params_control::{
            get_settled_param_vote_count, get_settled_pos_staking_for_votes,
            settle_current_votes, storage_point_prop, AllParamsVoteCount,
            ParamVoteCount,
        },
        pos::{
            decode_register_info, entries as pos_internal_entries,
            make_staking_events, IndexStatus,
        },
    },
};
