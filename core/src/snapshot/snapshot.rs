// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::path::Path;

// FIXME: find out how to organize synced snapshot data and snapshot recovery.
#[allow(unused)]
// Conflux snapshot wire-format.
pub struct Snapshot {
    // TODO(yz): implement.
}

// The trait is created to separate the implementation to another file, and the
// concrete struct is put into inner mod, because the implementation is
// anticipated to be too complex to present in the same file of the API.
// TODO(yz): check if this is the best way to organize code for this library.
pub trait SnapshotTrait {
    fn from_file(path: &Path) -> Self;
}
