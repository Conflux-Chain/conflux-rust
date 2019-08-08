// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait SnapshotDbTrait {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>>;
}

use super::super::impls::errors::*;
