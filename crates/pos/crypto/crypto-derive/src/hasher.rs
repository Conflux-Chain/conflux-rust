// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Converts a camel-case string to snake-case
pub fn camel_to_snake(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut first = true;
    text.chars().for_each(|c| {
        if !first && c.is_uppercase() {
            out.push('_');
            out.extend(c.to_lowercase());
        } else if first {
            first = false;
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    });
    out
}
