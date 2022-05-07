// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::preludes::*;
use cfx_parameters::internal_contract_addresses::SYSTEM_STORAGE_ADDRESS;

make_solidity_contract! {
    pub struct SystemStorage(SYSTEM_STORAGE_ADDRESS, SolFnTable::default, initialize: |params: &CommonParams| params.transition_numbers.cip94, is_active: |spec: &Spec| spec.cip94);
}
