// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! Snappy compression bindings.
extern crate libc;

use libc::{c_char, c_int, size_t};

pub const SNAPPY_OK: c_int = 0;
pub const SNAPPY_INVALID_INPUT: c_int = 1;
pub const SNAPPY_BUFFER_TOO_SMALL: c_int = 2;

extern {
	pub fn snappy_compress(
		input: *const c_char,
		input_len: size_t,
		compressed: *mut c_char,
		compressed_len: *mut size_t
	) -> c_int;

	pub fn snappy_max_compressed_length(source_len: size_t) -> size_t;

	pub fn snappy_uncompress(
		compressed: *const c_char,
		compressed_len: size_t,
		uncompressed: *mut c_char,
		uncompressed_len: *mut size_t,
	) -> c_int;

	pub fn snappy_uncompressed_length(
		compressed: *const c_char,
		compressed_len: size_t,
		result: *mut size_t,
	) -> c_int;

	pub fn snappy_validate_compressed_buffer(
		compressed: *const c_char,
		compressed_len: size_t,
	) -> c_int;
}
