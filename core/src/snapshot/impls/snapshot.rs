// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::snapshot::*;

use std::path::Path;

impl SnapshotTrait for Snapshot {
    fn from_file(_path: &Path) -> Self { unimplemented!() }
}
