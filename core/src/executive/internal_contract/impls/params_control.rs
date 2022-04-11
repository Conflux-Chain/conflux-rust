// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    executive::InternalRefContext,
    observer::{AddressPocket, VmObserve},
    state::cleanup_mode,
    vm::{self, ActionParams, Spec},
};
use cfx_state::{state_trait::StateOpsTrait, SubstateTrait};
use cfx_types::{
    address_util::AddressUtil, Address, AddressSpaceUtil, AddressWithSpace,
    Space, U256,
};

/// Implementation of `set_admin(address,address)`.
/// The input should consist of 20 bytes `contract_address` + 20 bytes
/// `new_admin_address`
pub fn cast_vote(
    contract_address: Address, new_admin_address: Address,
    params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()>
{
    todo!()
}

pub mod entries {
    use super::*;
    use cfx_types::H256;
    use tiny_keccak::{Hasher, Keccak};

    pub type StorageEntryKey = Vec<u8>;

    const CURRENT_TOTAL_VOTES_KEY: &'static [u8] = b"current_total_votes";
    const NEXT_TOTAL_VOTES_KEY: &'static [u8] = b"next_total_votes";

    const POW_BASE_REWARD_INDEX: u8 = 0;
    const POS_BASE_REWARD_INTEREST_RATE_INDEX: u8 = 1;

    const OPTION_UNCHANGE_INDEX: u8 = 0;
    const OPTION_INCREASE_INDEX: u8 = 1;
    const OPTION_DECREASE_INDEX: u8 = 2;

    fn prefix_and_hash(prefix: u64, data: &[u8]) -> StorageEntryKey {
        let mut hasher = Keccak::v256();
        hasher.update(&prefix.to_be_bytes());
        hasher.update(data);
        let mut hash = H256::default();
        hasher.finalize(hash.as_bytes_mut());
        hash.as_bytes().to_vec()
    }

    #[inline]
    pub fn start_entry(identifier: &H256) -> StorageEntryKey {
        prefix_and_hash(3, identifier.as_bytes())
    }
}
