// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::time::Duration;

#[derive(Clone)]
pub struct Configuration {
    // header sync parameters
    pub max_headers_in_flight: Option<usize>,
    pub header_request_batch_size: Option<usize>,
    pub header_request_timeout: Option<Duration>,

    // epoch sync parameters
    pub num_epochs_to_request: Option<usize>,
    pub max_parallel_epochs_to_request: Option<usize>,
    pub epoch_request_batch_size: Option<usize>,
    pub epoch_request_timeout: Option<Duration>,
    pub num_waiting_headers_threshold: Option<usize>,
}
