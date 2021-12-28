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
pub mod ed25519;
pub mod error;
pub mod hash;
pub mod hkdf;
/// A multi bls signature wrapper
pub mod multi_bls;
pub mod multi_ed25519;
pub mod noise;
pub mod test_utils;
pub mod traits;
/// VDF SHA256.
pub mod vdf_sha3;
pub mod x25519;

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

// We use [formally verified arithmetic](https://crates.io/crates/fiat-crypto)
// in maintained forks of the dalek suite of libraries ({curve, ed,
// x}25519-dalek). This is controlled by a feature in the forked crates
// ('fiat_u64_backend'), which we turn on by default.
#[cfg(not(any(feature = "fiat", feature = "u64", feature = "u32")))]
compile_error!(
    "no dalek arithmetic backend cargo feature enabled! \
     please enable one of: fiat, u64, u32"
);

#[cfg(all(feature = "fiat", feature = "u64"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

#[cfg(all(feature = "fiat", feature = "u32"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

#[cfg(all(feature = "u64", feature = "u32"))]
compile_error!(
    "at most one dalek arithmetic backend cargo feature should be enabled! \
     please enable exactly one of: fiat, u64, u32"
);

// MIRAI's tag analysis makes use of the incomplete const_generics feature, so
// the module containing the definitions of MIRAI tag types should not get
// compiled in a release build. The code below fails a build of the crate if
// mirai is on but debug_assertions is not.
#[cfg(all(mirai, not(debug_assertions)))]
compile_error!("MIRAI can only be used to compile the crate in a debug build!");
