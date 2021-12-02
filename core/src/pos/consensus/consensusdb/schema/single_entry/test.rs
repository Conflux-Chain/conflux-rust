// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use schemadb::schema::assert_encode_decode;

// Tests that the DB can encode / decode data
#[test]
fn test_single_entry_schema() {
    assert_encode_decode::<SingleEntrySchema>(
        &SingleEntryKey::HighestTimeoutCertificate,
        &vec![1u8, 2u8, 3u8],
    );
}
