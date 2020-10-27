// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Default)]
pub struct RpcImplConfiguration {
    pub get_logs_filter_max_limit: Option<usize>,
}

pub mod cfx;
pub mod common;
pub mod light;
pub mod pubsub;
