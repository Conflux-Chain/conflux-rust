// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{env, process::Command};

/// Save revision info to environment variable
fn main() {
    if env::var("GIT_REV").is_err() {
        let output = Command::new("git")
            .args(&["rev-parse", "--short", "HEAD"])
            .output()
            .unwrap();
        let git_rev = String::from_utf8(output.stdout).unwrap();
        println!("cargo:rustc-env=GIT_REV={}", git_rev);
    }
}
