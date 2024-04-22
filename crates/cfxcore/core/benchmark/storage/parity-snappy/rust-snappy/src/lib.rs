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
extern crate parity_snappy_sys;
#[cfg(test)]
extern crate rand;

use libc::size_t;
use parity_snappy_sys as snappy;
use std::fmt;

mod snappy_ffi {
	use libc::c_int;

	pub const SNAPPY_OK: c_int = 0;
	pub const SNAPPY_INVALID_INPUT: c_int = 1;
	pub const SNAPPY_BUFFER_TOO_SMALL: c_int = 2;
}

/// Attempted to decompress an uncompressed buffer.
#[derive(Debug)]
pub struct InvalidInput;

impl std::error::Error for InvalidInput {
	fn description(&self) -> &str {
		"Attempted snappy decompression with invalid input"
	}
}

impl fmt::Display for InvalidInput {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "Attempted snappy decompression with invalid input")
	}
}

/// The maximum compressed length given a size.
pub fn max_compressed_len(len: usize) -> usize {
	unsafe { snappy::snappy_max_compressed_length(len as size_t) as usize }
}

/// How large the given data will be when decompressed.
pub fn decompressed_len(compressed: &[u8]) -> Result<usize, InvalidInput> {
	let mut size: size_t = 0;
	let len = compressed.len() as size_t;

	let status = unsafe {
		snappy::snappy_uncompressed_length(compressed.as_ptr(), len, &mut size)
	};

	if status == snappy_ffi::SNAPPY_INVALID_INPUT {
		Err(InvalidInput)
	} else {
		Ok(size)
	}
}

/// Compress a buffer using snappy.
pub fn compress(input: &[u8]) -> Vec<u8> {
	let mut buf = Vec::new();
	let size = compress_into(input, &mut buf);
	buf.truncate(size);
	buf
}

/// Compress a buffer using snappy, writing the result into
/// the given output buffer, growing it if necessary.
/// Otherwise, returns the length of the compressed data.
pub fn compress_into(input: &[u8], output: &mut Vec<u8>) -> usize {
	let mut len = max_compressed_len(input.len());

	if output.len() < len {
		output.resize(len, 0);
	}

	let status = unsafe {
		snappy::snappy_compress(
			input.as_ptr(),
			input.len() as size_t,
			output.as_mut_ptr(),
			&mut len as &mut size_t,
		)
	};

	match status {
		snappy_ffi::SNAPPY_OK => len,
		snappy_ffi::SNAPPY_INVALID_INPUT => {
			panic!("snappy compression has no concept of invalid input")
		}
		snappy_ffi::SNAPPY_BUFFER_TOO_SMALL => {
			panic!("buffer cannot be too small, the capacity was just ensured.")
		}
		_ => panic!("snappy returned unspecified status"),
	}
}

/// Decompress a buffer using snappy. Will return an error if the buffer is not snappy-compressed.
pub fn decompress(input: &[u8]) -> Result<Vec<u8>, InvalidInput> {
	let mut v = Vec::new();
	decompress_into(input, &mut v).map(|_| v)
}

/// Decompress a buffer using snappy, writing the result into
/// the given output buffer, growing it if necessary.
/// Will error if the input buffer is not snappy-compressed.
/// Otherwise, returns the length of the decompressed data.
pub fn decompress_into(input: &[u8], output: &mut Vec<u8>) -> Result<usize, InvalidInput> {
	let mut len = decompressed_len(input)?;

	if output.len() < len {
		output.resize(len, 0);
	}

	let status = unsafe {
		snappy::snappy_uncompress(
			input.as_ptr(),
			input.len() as size_t,
			output.as_mut_ptr(),
			&mut len as &mut size_t,
		)
	};

	match status {
		snappy_ffi::SNAPPY_OK => Ok(len as usize),
		snappy_ffi::SNAPPY_INVALID_INPUT => Err(InvalidInput),
		snappy_ffi::SNAPPY_BUFFER_TOO_SMALL => {
			panic!("buffer cannot be too small, size was just set to large enough.")
		}
		_ => panic!("snappy returned unspecified status"),
	}
}

/// Validate a compressed buffer. True if valid, false if not.
pub fn validate_compressed_buffer(input: &[u8]) -> bool {
	let status = unsafe {
		snappy::snappy_validate_compressed_buffer(
			input.as_ptr(),
			input.len() as size_t,
		)
	};
	status == snappy_ffi::SNAPPY_OK
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::prelude::*;

	const ITERATIONS: usize = 100;
	const INPUT_SIZE: usize = 1 << 18;

	#[test]
	fn it_works() {
		let mut rng = thread_rng();
		let mut input = [0u8; INPUT_SIZE];

		for _ in 0..ITERATIONS {
			rng.fill(&mut input[..]);

			let output = decompress(&compress(&input));

			match output {
				Err(err) => panic!("failed with error: {} for input: {:?}", err, input.to_vec()),
				Ok(output) => assert_eq!(input.to_vec(), output),
			}
		}
	}
}
