// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(clippy::unit_arg)]

use anyhow::Result;
#[cfg(any(test, feature = "fuzzing"))]
use proptest::prelude::*;
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use serde::{de, ser, Deserialize, Serialize};
use std::{convert::TryFrom, fmt};

/// The minimum status code for validation statuses
pub static VALIDATION_STATUS_MIN_CODE: u64 = 0;

/// The maximum status code for validation statuses
pub static VALIDATION_STATUS_MAX_CODE: u64 = 999;

/// The minimum status code for runtime statuses
pub static EXECUTION_STATUS_MIN_CODE: u64 = 4000;

/// The maximum status code for runtime statuses
pub static EXECUTION_STATUS_MAX_CODE: u64 = 4999;

/// A `VMStatus` is represented as either
/// - `Executed` indicating successful execution
/// - `Error` indicating an error from the VM itself
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
#[cfg_attr(any(test, feature = "fuzzing"), proptest(no_params))]
pub enum VMStatus {
    /// The VM status corresponding to an EXECUTED status code
    Executed,

    /// Indicates an error from the VM, e.g. INVALID_SIGNATURE,
    /// CFX_INVALID_TX etc.
    Error(StatusCode),
}

#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
#[cfg_attr(any(test, feature = "fuzzing"), proptest(no_params))]
pub enum KeptVMStatus {
    Executed,
    MiscellaneousError,
}

pub type DiscardedVMStatus = StatusCode;

/// A status type is one of several variants, along with a fallback variant
/// in the case that we don't recognize the status code.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum StatusType {
    Validation,
    Execution,
    Unknown,
}

impl VMStatus {
    /// Return the status code for the `VMStatus`
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Executed => StatusCode::EXECUTED,
            Self::Error(code) => *code,
        }
    }

    /// Return the status type for this `VMStatus`. This is solely
    /// determined by the `status_code`
    pub fn status_type(&self) -> StatusType { self.status_code().status_type() }

    /// Returns `Ok` with a recorded status if it should be kept, `Err`
    /// of the error code if it should be discarded
    pub fn keep_or_discard(self) -> Result<KeptVMStatus, DiscardedVMStatus> {
        match self {
            VMStatus::Executed => Ok(KeptVMStatus::Executed),
            VMStatus::Error(code) => match code.status_type() {
                StatusType::Validation => Err(code),
                StatusType::Unknown => Err(code),
                StatusType::Execution => Ok(KeptVMStatus::MiscellaneousError),
            },
        }
    }
}

impl fmt::Display for StatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let string = match self {
            StatusType::Validation => "Validation",
            StatusType::Execution => "Execution",
            StatusType::Unknown => "Unknown",
        };
        write!(f, "{}", string)
    }
}

impl fmt::Display for VMStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status_type = self.status_type();
        write!(
            f,
            "status {:#?} of type {}",
            self.status_code(),
            status_type
        )
    }
}

impl fmt::Display for KeptVMStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "status ")?;
        match self {
            KeptVMStatus::Executed => write!(f, "EXECUTED"),
            KeptVMStatus::MiscellaneousError => {
                write!(f, "MISCELLANEOUS_ERROR")
            }
        }
    }
}

impl fmt::Debug for VMStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMStatus::Executed => write!(f, "EXECUTED"),
            VMStatus::Error(code) => {
                f.debug_struct("ERROR").field("status_code", code).finish()
            }
        }
    }
}

impl fmt::Debug for KeptVMStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeptVMStatus::Executed => write!(f, "EXECUTED"),
            KeptVMStatus::MiscellaneousError => {
                write!(f, "MISCELLANEOUS_ERROR")
            }
        }
    }
}

impl std::error::Error for VMStatus {}

macro_rules! derive_status_try_from_repr {
    (
        #[repr($repr_ty:ident)]
        $( #[$metas:meta] )*
        $vis:vis enum $enum_name:ident {
            $(
                $variant:ident = $value: expr
            ),*
            $( , )?
        }
    ) => {
        #[repr($repr_ty)]
        $( #[$metas] )*
        $vis enum $enum_name {
            $(
                $variant = $value
            ),*
        }

        impl std::convert::TryFrom<$repr_ty> for $enum_name {
            type Error = &'static str;
            fn try_from(value: $repr_ty) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok($enum_name::$variant),
                    )*
                    _ => Err("invalid StatusCode"),
                }
            }
        }

        #[cfg(any(test, feature = "fuzzing"))]
        const STATUS_CODE_VALUES: &'static [$repr_ty] = &[
            $($value),*
        ];
    };
}

derive_status_try_from_repr! {
#[repr(u64)]
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum StatusCode {
    // Validation Errors: 0-999
    UNKNOWN_VALIDATION_STATUS = 0,
    INVALID_SIGNATURE = 1,
    // The transaction is not expected for Conflux PoS chain
    CFX_UNEXPECTED_TX = 27,
    // The pos transaction does not pass validation based on pos state
    CFX_INVALID_TX = 28,
    ELECTION_NON_EXISTENT_NODE = 29,
    ELECTION_TARGET_TERM_NOT_OPEN = 31,
    ELECTION_WITHOUT_VOTES = 32,
    PIVOT_DECISION_HEIGHT_TOO_OLD = 33,

    // Runtime Errors: 4000-4999
    EXECUTED = 4001,

    // A reserved status to represent an unknown vm status.
    UNKNOWN_STATUS = 18446744073709551615,
}
}

impl StatusCode {
    /// Return the status type for this status code
    pub fn status_type(self) -> StatusType {
        let major_status_number: u64 = self.into();
        if major_status_number >= VALIDATION_STATUS_MIN_CODE
            && major_status_number <= VALIDATION_STATUS_MAX_CODE
        {
            return StatusType::Validation;
        }

        if major_status_number >= EXECUTION_STATUS_MIN_CODE
            && major_status_number <= EXECUTION_STATUS_MAX_CODE
        {
            return StatusType::Execution;
        }

        StatusType::Unknown
    }
}

// TODO(#1307)
impl ser::Serialize for StatusCode {
    fn serialize<S>(
        &self, serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where S: ser::Serializer {
        serializer.serialize_u64((*self).into())
    }
}

impl<'de> de::Deserialize<'de> for StatusCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: de::Deserializer<'de> {
        struct StatusCodeVisitor;
        impl<'de> de::Visitor<'de> for StatusCodeVisitor {
            type Value = StatusCode;

            fn expecting(
                &self, formatter: &mut fmt::Formatter<'_>,
            ) -> fmt::Result {
                formatter.write_str("StatusCode as u64")
            }

            fn visit_u64<E>(
                self, v: u64,
            ) -> std::result::Result<StatusCode, E>
            where E: de::Error {
                Ok(StatusCode::try_from(v)
                    .unwrap_or(StatusCode::UNKNOWN_STATUS))
            }
        }

        deserializer.deserialize_u64(StatusCodeVisitor)
    }
}

impl From<StatusCode> for u64 {
    fn from(status: StatusCode) -> u64 { status as u64 }
}

/// The `Arbitrary` impl only generates validation statuses since the
/// full enum is too large.
#[cfg(any(test, feature = "fuzzing"))]
impl Arbitrary for StatusCode {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: ()) -> Self::Strategy {
        (any::<usize>())
            .prop_map(|index| {
                let status_code_value =
                    STATUS_CODE_VALUES[index % STATUS_CODE_VALUES.len()];
                StatusCode::try_from(status_code_value).unwrap()
            })
            .boxed()
    }
}

#[test]
fn test_status_codes() {
    use std::collections::HashSet;
    // Make sure that within the 0-EXECUTION_STATUS_MAX_CODE that all
    // of the status codes succeed when they should, and fail when
    // they should.
    for possible_major_status_code in 0..=EXECUTION_STATUS_MAX_CODE {
        if STATUS_CODE_VALUES.contains(&possible_major_status_code) {
            let status = StatusCode::try_from(possible_major_status_code);
            assert!(status.is_ok());
            let to_major_status_code = u64::from(status.unwrap());
            assert_eq!(possible_major_status_code, to_major_status_code);
        } else {
            assert!(StatusCode::try_from(possible_major_status_code).is_err())
        }
    }

    let mut seen_statuses = HashSet::new();
    let mut seen_codes = HashSet::new();
    // Now make sure that all of the error codes (including any that
    // may be out-of-range) succeed. Make sure there aren't any
    // duplicate mappings
    for major_status_code in STATUS_CODE_VALUES.iter() {
        assert!(
            !seen_codes.contains(major_status_code),
            "Duplicate major_status_code found"
        );
        seen_codes.insert(*major_status_code);
        let status = StatusCode::try_from(*major_status_code);
        assert!(status.is_ok());
        let unwrapped_status = status.unwrap();
        assert!(
            !seen_statuses.contains(&unwrapped_status),
            "Found duplicate u64 -> Status mapping"
        );
        seen_statuses.insert(unwrapped_status);
        let to_major_status_code = u64::from(unwrapped_status);
        assert_eq!(*major_status_code, to_major_status_code);
    }
}
