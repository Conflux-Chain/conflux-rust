// Copyright 2023-2024 Paradigm.xyz
// This file is part of reth.
// Reth is a modular, contributor-friendly and blazing-fast implementation of
// the Ethereum protocol

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::fmt::Write;

use jsonrpsee_types::SubscriptionId;

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct CfxSubscriptionIdProvider;

impl jsonrpsee_core::traits::IdProvider for CfxSubscriptionIdProvider {
    fn next_id(&self) -> SubscriptionId<'static> {
        to_quantity(rand::random::<u128>())
    }
}

#[inline(always)]
fn to_quantity(val: u128) -> SubscriptionId<'static> {
    let bytes = val.to_be_bytes();
    let b = bytes.as_slice();
    let non_zero = b.iter().take_while(|b| **b == 0).count();
    let b = &b[non_zero..];
    if b.is_empty() {
        return SubscriptionId::Str("0x0".into());
    }

    let mut id = String::with_capacity(2 * b.len() + 2);
    id.push_str("0x");
    let first_byte = b[0];
    write!(id, "{first_byte:x}").unwrap();

    for byte in &b[1..] {
        write!(id, "{byte:02x}").unwrap();
    }
    id.into()
}
