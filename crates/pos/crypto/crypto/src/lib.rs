// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! This feature gets turned on only if diem-crypto is compiled via MIRAI in a
//! nightly build.
#![cfg_attr(mirai, allow(incomplete_features), feature(const_generics))]

//! A library supplying various cryptographic primitives

/// A BLS signature wrapper
pub mod bls;
pub mod compat;
/// A Elliptic Curve VRF wrapper
pub mod ec_vrf;
pub mod error;
pub mod hash;
/// A multi bls signature wrapper
pub mod multi_bls;
pub mod test_utils;
pub mod traits;
#[cfg(test)]
mod unit_tests;

/// Utility to store encrypted private keys
pub mod key_file;
#[cfg(mirai)]
mod tags;

pub use self::traits::*;
pub use hash::HashValue;

// Reexport once_cell and serde_name for use in CryptoHasher Derive
// implementation.
#[doc(hidden)]
pub use once_cell as _once_cell;
#[doc(hidden)]
pub use serde_name as _serde_name;

// MIRAI's tag analysis makes use of the incomplete const_generics feature, so
// the module containing the definitions of MIRAI tag types should not get
// compiled in a release build. The code below fails a build of the crate if
// mirai is on but debug_assertions is not.
#[cfg(all(mirai, not(debug_assertions)))]
compile_error!("MIRAI can only be used to compile the crate in a debug build!");
