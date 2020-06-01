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

#![feature(test)]
extern crate test;

extern crate parity_snappy as snappy;
extern crate rand;

#[cfg(test)]
mod tests {
	use rand::prelude::*;
	use snappy;
	use test::Bencher;

	const INPUT_SIZE: usize = 1 << 19;

	#[bench]
	fn bench_compress_decompress(b: &mut Bencher) {
		let mut rng = StdRng::from_seed([0u8; 32]);
		let mut input = [0u8; INPUT_SIZE];
		rng.fill(&mut input[..]);

		let mut compressed = Vec::with_capacity(INPUT_SIZE);
		let mut decompressed = Vec::with_capacity(INPUT_SIZE);

		b.iter(|| {
			let size = snappy::compress_into(&input, &mut compressed);
			let _ = snappy::decompress_into(&compressed[..size], &mut decompressed);
		});
	}
}
