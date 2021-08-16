// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use schemadb::schema::assert_encode_decode;

#[test]
fn test_encode_decode() {
    assert_encode_decode::<TransactionAccumulatorSchema>(
        &Position::from_inorder_index(100),
        &HashValue::random(),
    );
}
