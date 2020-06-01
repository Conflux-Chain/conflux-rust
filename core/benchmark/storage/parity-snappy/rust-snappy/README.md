# parity-snappy

[![Build Status](https://travis-ci.org/paritytech/rust-snappy.svg?branch=master)](https://travis-ci.org/paritytech/rust-snappy)
[![Build status](https://ci.appveyor.com/api/projects/status/rr3ipesm4qqwv7y1?svg=true)](https://ci.appveyor.com/project/andresilva/rust-snappy)

Rust bindings for the snappy compression library.

Currently this library uses snappy v1.1.7. The source for snappy is included in the `parity-snappy-sys` crate, so
there's no need to pre-install snappy, and the library will be statically linked.

## Example

```rust
use parity_snappy as snappy;

let input: Vec<u8> = ...;
let compressed = snappy::compress(&input);
let decompressed = snappy::decompress(&compressed);

assert_eq!(decompressed == input);
```

```rust
use parity_snappy as snappy;

let input: Vec<u8> = ...;
let mut compressed = Vec::with_capacity(snappy::max_compressed_len(input.len()));
let mut decompressed = Vec::with_capacity(input.len());

let len = snappy::compress_into(&input, &mut compressed);
let _ = snappy::decompress_into(&compressed[..len], &mut decompressed);

assert_eq!(decompressed == input);
```
