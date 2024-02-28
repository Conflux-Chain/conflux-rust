// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod proof_test;
mod write_test;

use super::*;
use crate::test_helpers::{
    arb_hash_batch, test_get_frozen_subtree_hashes_impl,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_get_frozen_subtree_hashes(leaves in arb_hash_batch(1000)) {
        test_get_frozen_subtree_hashes_impl(leaves);
    }
}
