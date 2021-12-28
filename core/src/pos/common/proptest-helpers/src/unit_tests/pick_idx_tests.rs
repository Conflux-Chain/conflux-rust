// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{pick_slice_idxs, Index};
use proptest::{collection::vec, prelude::*};
use std::collections::HashSet;

proptest! {
    /// All values returned from `pick_slice_idxs` are in bounds.
    #[test]
    fn bounds(total_len in 0..100usize, idxs in vec(any::<Index>(), 0..200usize)) {
        prop_assert!(pick_slice_idxs(total_len, &idxs).into_iter().all(|idx| idx < total_len));
    }

    /// There's no duplication in the values returned from `pick_slice_idxs`.
    #[test]
    fn uniqueness(total_len in 0..100usize, idxs in vec(any::<Index>(), 0..200usize)) {
        let picked = pick_slice_idxs(total_len, &idxs);
        let picked_len = picked.len();
        let picked_set: HashSet<_> = picked.into_iter().collect();
        prop_assert_eq!(picked_set.len(), picked_len);
        prop_assert!(picked_len <= total_len);
    }

    /// The number of items returned is the same as the number requested or the total length,
    /// whichever's smaller.
    #[test]
    fn length(total_len in 0..100usize, idxs in vec(any::<Index>(), 0..200usize)) {
        let picked = pick_slice_idxs(total_len, &idxs);
        let picked_len = picked.len();
        let expected_len = total_len.min(idxs.len());
        prop_assert_eq!(expected_len, picked_len);
    }
}
