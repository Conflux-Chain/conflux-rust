// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Open Ethereum.

// Open Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Open Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Open Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use super::super::instructions::{self, Instruction};
use crate::hash::KECCAK_EMPTY;
use bit_set::BitSet;
use cfx_types::H256;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use memory_cache::MemoryLruCache;
use parking_lot::Mutex;
use std::sync::Arc;

const DEFAULT_CACHE_SIZE: usize = 4 * 1024 * 1024;

/// Stub for a sharing `BitSet` data in cache (reference counted)
/// and implementing MallocSizeOf on it.
#[derive(Clone)]
struct Bits(Arc<BitSet>);

impl MallocSizeOf for Bits {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        // dealing in bits here
        self.0.capacity() * 8
    }
}

#[derive(Clone)]
struct CacheItem {
    jump_destination: Bits,
    sub_entrypoint: Bits,
}

impl MallocSizeOf for CacheItem {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.jump_destination.size_of(ops) + self.sub_entrypoint.size_of(ops)
    }
}

/// Global cache for EVM interpreter
pub struct SharedCache {
    jump_destinations: Mutex<MemoryLruCache<H256, CacheItem>>,
}

impl SharedCache {
    /// Create a jump destinations cache with a maximum size in bytes
    /// to cache.
    pub fn new(max_size: usize) -> Self {
        SharedCache {
            jump_destinations: Mutex::new(MemoryLruCache::new(max_size)),
        }
    }

    /// Get jump destinations bitmap for a contract.
    pub fn jump_and_sub_destinations(
        &self, code_hash: &Option<H256>, code: &[u8],
    ) -> (Arc<BitSet>, Arc<BitSet>) {
        if let Some(ref code_hash) = code_hash {
            if code_hash == &KECCAK_EMPTY {
                let cache_item = Self::find_jump_and_sub_destinations(code);
                return (
                    cache_item.jump_destination.0,
                    cache_item.sub_entrypoint.0,
                );
            }

            if let Some(d) = self.jump_destinations.lock().get_mut(code_hash) {
                return (
                    d.jump_destination.0.clone(),
                    d.sub_entrypoint.0.clone(),
                );
            }
        }

        let d = Self::find_jump_and_sub_destinations(code);

        if let Some(ref code_hash) = code_hash {
            self.jump_destinations.lock().insert(*code_hash, d.clone());
        }

        (d.jump_destination.0, d.sub_entrypoint.0)
    }

    fn find_jump_and_sub_destinations(code: &[u8]) -> CacheItem {
        let mut jump_dests = BitSet::with_capacity(code.len());
        let mut sub_entrypoints = BitSet::with_capacity(code.len());
        let mut position = 0;

        while position < code.len() {
            let instruction = Instruction::from_u8(code[position]);

            if let Some(instruction) = instruction {
                match instruction {
                    instructions::JUMPDEST => {
                        jump_dests.insert(position);
                    }
                    instructions::BEGINSUB => {
                        sub_entrypoints.insert(position);
                    }
                    _ => {
                        if let Some(push_bytes) = instruction.push_bytes() {
                            position += push_bytes;
                        }
                    }
                }
            }
            position += 1;
        }

        jump_dests.shrink_to_fit();
        CacheItem {
            jump_destination: Bits(Arc::new(jump_dests)),
            sub_entrypoint: Bits(Arc::new(sub_entrypoints)),
        }
    }
}

impl Default for SharedCache {
    fn default() -> Self { SharedCache::new(DEFAULT_CACHE_SIZE) }
}

#[test]
fn test_find_jump_destinations() {
    use rustc_hex::FromHex;
    // given

    // 0000 7F   PUSH32
    // 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // 0021 7F   PUSH32
    // 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    // 0042 5B   JUMPDEST
    // 0043 01   ADD
    // 0044 60   PUSH1 0x00
    // 0046 55   SSTORE
    let code = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5b01600055".from_hex().unwrap();

    // when
    let cache_item = SharedCache::find_jump_and_sub_destinations(&code);

    // then
    assert!(cache_item
        .jump_destination
        .0
        .iter()
        .eq(vec![66].into_iter()));
    assert!(cache_item.sub_entrypoint.0.is_empty());
}

#[test]
fn test_find_jump_destinations_not_in_data_segments() {
    use rustc_hex::FromHex;
    // given

    // 0000 60 06   PUSH1 06
    // 0002 56      JUMP
    // 0003 50 5B   PUSH1 0x5B
    // 0005 56      STOP
    // 0006 5B      JUMPDEST
    // 0007 60 04   PUSH1 04
    // 0009 56      JUMP
    let code = "600656605B565B6004".from_hex().unwrap();

    // when
    let cache_item = SharedCache::find_jump_and_sub_destinations(&code);

    // then
    assert!(cache_item.jump_destination.0.iter().eq(vec![6].into_iter()));
    assert!(cache_item.sub_entrypoint.0.is_empty());
}

#[test]
fn test_find_sub_entrypoints() {
    use rustc_hex::FromHex;
    // given

    // see https://eips.ethereum.org/EIPS/eip-2315 for disassembly
    let code = "6800000000000000000c5e005c60115e5d5c5d".from_hex().unwrap();

    // when
    let cache_item = SharedCache::find_jump_and_sub_destinations(&code);

    // then
    assert!(cache_item.jump_destination.0.is_empty());
    assert!(cache_item
        .sub_entrypoint
        .0
        .iter()
        .eq(vec![12, 17].into_iter()));
}

#[test]
fn test_find_jump_and_sub_allowing_unknown_opcodes() {
    use rustc_hex::FromHex;
    // precondition
    assert!(Instruction::from_u8(0xcc) == None);

    // given

    // 0000 5B   JUMPDEST
    // 0001 CC   ???
    // 0002 5C   BEGINSUB
    let code = "5BCC5C".from_hex().unwrap();

    // when
    let cache_item = SharedCache::find_jump_and_sub_destinations(&code);

    // then
    assert!(cache_item.jump_destination.0.iter().eq(vec![0].into_iter()));
    assert!(cache_item.sub_entrypoint.0.iter().eq(vec![2].into_iter()));
}
