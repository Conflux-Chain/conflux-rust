// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use consensus_types::block::block_test_utils::certificate_for_genesis;
use schemadb::schema::assert_encode_decode;

#[test]
fn test_encode_decode() {
    let qc = certificate_for_genesis();
    assert_encode_decode::<QCSchema>(&qc.certified_block().id(), &qc);
}
