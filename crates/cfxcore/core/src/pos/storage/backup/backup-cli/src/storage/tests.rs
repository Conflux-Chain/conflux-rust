// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::storage::ShellSafeName;
use std::str::FromStr;

#[test]
fn test_shell_safe_name() {
    assert!(ShellSafeName::from_str(".hidden").is_err());
    assert!(ShellSafeName::from_str(".").is_err());
    assert!(ShellSafeName::from_str("..").is_err());
    assert!(ShellSafeName::from_str("-m").is_err());
    assert!(ShellSafeName::from_str("a b").is_err());
    assert!(ShellSafeName::from_str("a\nb").is_err());
    assert!(ShellSafeName::from_str("ab?").is_err());
    assert!(ShellSafeName::from_str(&"x".repeat(128)).is_err());

    assert!(ShellSafeName::from_str(&"x".repeat(127)).is_ok());
}
