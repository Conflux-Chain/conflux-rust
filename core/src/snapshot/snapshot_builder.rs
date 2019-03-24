// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::snapshot::Snapshot;

// Build snapshot
#[allow(dead_code)]
pub struct SnapshotBuilder {}

trait SnapshotBuilderTrait {
    // TODO(yz): methods to add content into snapshot.

    fn build() -> Snapshot;
}
