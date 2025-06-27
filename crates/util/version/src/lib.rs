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

use target_info::Target;

/// Get the platform identifier.
pub fn platform() -> String {
    let env = Target::env();
    let env_dash = if env.is_empty() { "" } else { "-" };
    format!("{}-{}{}{}", Target::arch(), Target::os(), env_dash, env)
}

/// Get the standard version string for this software.
pub fn version(crate_version: &str) -> String {
    let sha3 = env!("VERGEN_GIT_SHA");
    let sha3_dash = if sha3.is_empty() { "" } else { "-" };
    let commit_date = env!("VERGEN_GIT_COMMIT_DATE").replace("-", "");
    let date_dash = if commit_date.is_empty() { "" } else { "-" };
    format!(
        "conflux-rust/v{}{}{}{}{}/{}/rustc{}",
        crate_version,
        sha3_dash,
        sha3,
        date_dash,
        commit_date,
        platform(),
        env!("VERGEN_RUSTC_SEMVER"),
    )
}

#[macro_export]
macro_rules! conflux_client_version {
    () => {
        parity_version::version(env!("CARGO_PKG_VERSION"))
    };
}

#[cfg(test)]

mod tests {
    use crate::{platform, version};

    use super::Target;

    #[test]
    fn test_platform() {
        let platform = platform();

        assert!(!platform.is_empty());
        assert!(platform.contains(Target::arch()));
        assert!(platform.contains(Target::os()));
    }

    #[test]
    fn test_version() {
        let test_version = "0.0.0";
        let version_string = version(test_version);
        // example:  conflux-rust/v0.0.0-b7cca2a-20250423/x86_64-linux-gnu/

        println!("version_string: {}", version_string);
        assert!(version_string
            .starts_with(&format!("conflux-rust/v{}", test_version)));
        assert!(version_string.contains(&format!("{}", platform())));

        let sha = env!("VERGEN_GIT_SHA");

        assert!(version_string.contains(&format!("-{}", sha)));
        let commit_date = env!("VERGEN_GIT_COMMIT_DATE").replace("-", "");

        assert_eq!(commit_date.len(), 8);
        assert!(version_string.contains(&format!("-{}", commit_date)));

        let rust_version = env!("VERGEN_RUSTC_SEMVER");
        assert!(version_string.contains(&format!("/rustc{}", rust_version)));
    }
}
