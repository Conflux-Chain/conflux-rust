// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use proptest::prelude::*;
use schemadb::schema::assert_encode_decode;

proptest! {
    #[test]
    fn test_encode_decode(
        address in any::<AccountAddress>(),
        seq_num in any::<u64>(),
        version in any::<Version>(),
    ) {
        assert_encode_decode::<TransactionByAccountSchema>(&(address, seq_num), &version);
    }
}
