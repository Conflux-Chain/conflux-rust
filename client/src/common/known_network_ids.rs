// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_addr::Network;

pub fn network_id_to_known_cfx_network(id: u64) -> Network {
    match id {
        1 => Network::Test,
        1029 => Network::Main,
        n => Network::Id(n),
    }
}
