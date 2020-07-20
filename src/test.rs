// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::U256;

#[test]
#[should_panic]
fn underflow_can_not_happen_u256() {
    let mut balance = U256::one();
    balance -= 2.into();
}

#[test]
#[should_panic]
fn underflow_can_not_happen_native_u64() {
    let mut balance = 1u64;
    balance -= 2;
    // To mute compiler warning about balance not used.
    let _max = balance;
}
