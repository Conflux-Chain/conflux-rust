// Copyright 2022 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of OpenEthereum.

// OpenEthereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// OpenEthereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with OpenEthereum.  If not, see <http://www.gnu.org/licenses/>.

//! Parity version specific information.

extern crate target_info;

use target_info::Target;

mod vergen {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

mod generated {
    include!(concat!(env!("OUT_DIR"), "/meta.rs"));
}

/// Get the platform identifier.
pub fn platform() -> String {
    let env = Target::env();
    let env_dash = if env.is_empty() { "" } else { "-" };
    format!("{}-{}{}{}", Target::arch(), Target::os(), env_dash, env)
}

/// Get the standard version string for this software.
pub fn version(crate_version: &str) -> String {
    let sha3 = vergen::short_sha();
    let sha3_dash = if sha3.is_empty() { "" } else { "-" };
    let commit_date = vergen::commit_date().replace("-", "");
    let date_dash = if commit_date.is_empty() { "" } else { "-" };
    format!(
        "conflux-rust/v{}{}{}{}{}/{}/rustc{}",
        crate_version,
        sha3_dash,
        sha3,
        date_dash,
        commit_date,
        platform(),
        generated::rustc_version()
    )
}
