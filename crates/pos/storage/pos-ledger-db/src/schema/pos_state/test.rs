// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use diem_types::term_state::pos_state_config::{
    PosStateConfig, POS_STATE_CONFIG,
};
use proptest::prelude::*;
use schemadb::schema::assert_encode_decode;

/// The encoding reads the CIP-173 transition view, so the codec needs a config.
fn install_config() { POS_STATE_CONFIG.get_or_init(PosStateConfig::default); }

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10,
        .. ProptestConfig::default()
    })]
    #[test]
    fn test_encode_decode(
        block_id in any::<HashValue>(),
        pos_state in any::<PosState>(),
    ) {
        install_config();
        assert_encode_decode::<PosStateSchema>(&block_id, &pos_state);
    }
}
