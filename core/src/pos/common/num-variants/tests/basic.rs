// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(dead_code)]

// TODO: There are no negative tests at the moment (e.g. deriving NumVariants on
// a struct or union). Add some, possibly using compiletest-rs: https://github.com/laumann/compiletest-rs

use num_variants::NumVariants;

#[derive(NumVariants)]
enum BasicEnum {
    A,
    B(usize),
    C { foo: String },
}

#[derive(NumVariants)]
enum ZeroEnum {}

#[derive(NumVariants)]
#[num_variants = "CUSTOM_NAME"]
enum CustomName {
    Foo,
    Bar,
    Baz,
}

#[test]
fn basic_enum() {
    assert_eq!(BasicEnum::NUM_VARIANTS, 3);
}

#[test]
fn zero_enum() {
    assert_eq!(ZeroEnum::NUM_VARIANTS, 0);
}

#[test]
fn custom_name() {
    assert_eq!(CustomName::CUSTOM_NAME, 3);
}
