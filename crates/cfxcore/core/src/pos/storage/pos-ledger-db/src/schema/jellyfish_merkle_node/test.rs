// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use diem_crypto::HashValue;
use diem_jellyfish_merkle::node_type::Node;
use diem_types::account_state_blob::AccountStateBlob;
use proptest::prelude::*;
use schemadb::schema::assert_encode_decode;

proptest! {
    #[test]
    fn test_jellyfish_merkle_node_schema(
        node_key in any::<NodeKey>(),
        account_key in any::<HashValue>(),
        blob in any::<AccountStateBlob>(),
    ) {
        assert_encode_decode::<JellyfishMerkleNodeSchema>(
            &node_key,
            &Node::new_leaf(account_key, blob),
        );
    }
}
