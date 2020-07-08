use super::{
    cache::{Cache, CacheBuilder},
    keccak::{keccak_256, keccak_512, H256},
    seed_compute::SeedHashCompute,
    shared::*,
};
use std::{mem, sync::Arc};

const MIX_WORDS: usize = POW_MIX_BYTES / 4;
const MIX_NODES: usize = MIX_WORDS / NODE_WORDS;
pub const FNV_PRIME: u32 = 0x01000193;
const MOD: u32 = 1000000000 + 7;
const MOD64: u64 = MOD as u64;

pub struct Light {
    block_height: u64,
    cache: Arc<Cache>,
}

/// Light cache structure
impl Light {
    pub fn new_with_builder(builder: &CacheBuilder, block_height: u64) -> Self {
        let cache = builder.new_cache(block_height);

        Light {
            block_height,
            cache,
        }
    }

    /// Calculate the light boundary data
    /// `header_hash` - The header hash to pack into the mix
    /// `nonce` - The nonce to pack into the mix
    pub fn compute(&self, header_hash: &H256, nonce: u64) -> H256 {
        light_compute(self, header_hash, nonce)
    }
}

#[allow(dead_code)]
pub fn slow_hash_block_height(block_height: u64) -> H256 {
    SeedHashCompute::resume_compute_seedhash([0u8; 32], 0, stage(block_height))
}

fn fnv_hash(x: u32, y: u32) -> u32 { return x.wrapping_mul(FNV_PRIME) ^ y; }

// /// Difficulty quick check for POW preverification
// ///
// /// `header_hash`      The hash of the header
// /// `nonce`            The block's nonce
// /// `mix_hash`         The mix digest hash
// /// Boundary recovered from mix hash
// pub fn quick_get_difficulty(header_hash: &H256, nonce: u64, mix_hash: &H256)
// -> H256 { 	unsafe {
//         let mut buf = [0u8; 64 + 32];

//         let hash_len = header_hash.len();
//         buf[..hash_len].copy_from_slice(header_hash);
//         let end = hash_len + mem::size_of::<u64>();
//         buf[hash_len..end].copy_from_slice(&nonce.to_ne_bytes());

//         keccak_512::inplace_range(&mut buf, 0..end);
//         buf[64..].copy_from_slice(mix_hash);

//         let mut hash = [0u8; 32];
//         keccak_256::write(&buf, &mut hash);

//         hash
// 	}
// }

/// Calculate the light client data
/// `light` - The light client handler
/// `header_hash` - The header hash to pack into the mix
/// `nonce` - The nonce to pack into the mix
pub fn light_compute(light: &Light, header_hash: &H256, nonce: u64) -> H256 {
    let full_size = get_data_size(light.block_height);
    hash_compute(light, full_size, header_hash, nonce)
}

fn as_u32_le(bytes: &[u8]) -> u32 {
    assert!(bytes.len() == 4);

    ((bytes[0] as u32) << 0)
        + ((bytes[1] as u32) << 8)
        + ((bytes[2] as u32) << 16)
        + ((bytes[3] as u32) << 24)
}

fn hash_compute(
    light: &Light, full_size: usize, header_hash: &H256, nonce: u64,
) -> H256 {
    macro_rules! make_const_array {
        ($n:expr, $value:expr) => {{
            // We use explicit lifetimes to ensure that val's borrow is
            // invalidated until the transmuted val dies.
            unsafe fn make_const_array<T, U>(val: &mut [T]) -> &mut [U; $n] {
                use ::std::mem;

                debug_assert_eq!(
                    val.len() * mem::size_of::<T>(),
                    $n * mem::size_of::<U>()
                );
                &mut *(val.as_mut_ptr() as *mut [U; $n])
            }

            make_const_array($value)
        }};
    }

    #[repr(C)]
    struct MixBuf {
        half_mix: Node,
        compress_bytes: [u8; MIX_WORDS],
        magic_mix: u32,
    };

    if full_size % MIX_WORDS != 0 {
        panic!("Unaligned full size");
    }

    // You may be asking yourself: what in the name of Crypto Jesus is going on
    // here? So: we need `half_mix` and `compress_bytes` in a single array
    // later down in the code (we hash them together to create `value`) so
    // that we can hash the full array. However, we do a bunch of
    // reading and writing to these variables first. We originally allocated two
    // arrays and then stuck them together with `ptr::copy_nonoverlapping`
    // at the end, but this method is _significantly_ faster - by my
    // benchmarks, a consistent 3-5%. This is the most ridiculous
    // optimization I have ever done and I am so sorry. I can only chalk it up
    // to cache locality improvements, since I can't imagine that 3-5% of
    // our runtime is taken up by catting two arrays together.
    let mut buf: MixBuf = MixBuf {
        half_mix: {
            // Pack `header_hash` and `nonce` together
            let mut out = [0u8; NODE_BYTES];

            let hash_len = header_hash.len();
            out[..hash_len].copy_from_slice(header_hash);
            let end = hash_len + mem::size_of::<u64>();
            out[hash_len..end].copy_from_slice(&nonce.to_ne_bytes());

            // compute keccak-512 hash and replicate across mix
            let mut tmp = [0u8; NODE_BYTES];
            keccak_512::write(&out[0..end], &mut tmp);
            out.copy_from_slice(&tmp);

            Node { bytes: out }
        },
        compress_bytes: [0u8; MIX_WORDS],
        magic_mix: 0,
    };

    let mut mix: [_; MIX_NODES] = [buf.half_mix.clone(), buf.half_mix.clone()];

    let page_size = 4 * MIX_WORDS;
    let num_full_pages = (full_size / page_size) as u32;
    // deref once for better performance
    let cache: &[Node] = light.cache.as_ref();
    let first_val = buf.half_mix.as_words()[0];

    let magic_b0 = as_u32_le(&header_hash[0..4]);
    let magic_b1 = as_u32_le(&header_hash[4..8]);
    let magic_b2 = as_u32_le(&header_hash[8..12]);
    let magic_w = as_u32_le(&header_hash[12..16]);
    let mut magic_c: [u32; POW_ACCESSES] = [0; POW_ACCESSES];

    debug_assert_eq!(MIX_NODES, 2);
    debug_assert_eq!(NODE_WORDS, 16);

    for i in 0..POW_ACCESSES as u32 {
        let index = {
            // This is trivially safe, but does not work on big-endian. The
            // safety of this is asserted in debug builds (see the
            // definition of `make_const_array!`).
            let mix_words: &mut [u32; MIX_WORDS] =
                unsafe { make_const_array!(MIX_WORDS, &mut mix) };

            fnv_hash(first_val ^ i, mix_words[i as usize % MIX_WORDS])
                % num_full_pages
        };

        // MIX_NODES
        for n in 0..2 {
            let tmp_node =
                calculate_dag_item(index * MIX_NODES as u32 + n as u32, cache);

            // NODE_WORDS
            for (a, b) in
                mix[n].as_words_mut().iter_mut().zip(tmp_node.as_words())
            {
                *a = fnv_hash(*a, *b);
                magic_c[i as usize] = magic_c[i as usize] ^ *a;
            }
        }
    }

    let mix_words: [u32; MIX_WORDS] = unsafe { mem::transmute(mix) };

    {
        // We iterate precisely `compress.len()` times and set each index,
        // leaving the array fully initialized. THIS ONLY WORKS ON LITTLE-ENDIAN
        // MACHINES. See a future PR to make this and the rest of the
        // code work correctly on big-endian arches like mips.
        let compress: &mut [u32; MIX_WORDS / 4] = unsafe {
            make_const_array!(MIX_WORDS / 4, &mut buf.compress_bytes)
        };

        // Compress mix
        debug_assert_eq!(MIX_WORDS / 4, 8);
        for i in 0..8 {
            let w = i * 4;

            let mut reduction = mix_words[w + 0];
            reduction = reduction.wrapping_mul(FNV_PRIME) ^ mix_words[w + 1];
            reduction = reduction.wrapping_mul(FNV_PRIME) ^ mix_words[w + 2];
            reduction = reduction.wrapping_mul(FNV_PRIME) ^ mix_words[w + 3];
            compress[i] = reduction;
        }
    }

    let mut magic_mix: [u32; POW_ACCESSES] = [0; POW_ACCESSES];

    for i in 0..POW_ACCESSES as usize {
        let mut p: u64 = (magic_b2 as u64) % MOD64;
        let mut q: u64 = (magic_b1 as u64) % MOD64;
        for _ in 0..i as usize {
            p = ((p * (magic_w as u64)) % MOD64 * (magic_w as u64)) % MOD64;
            q = (q * (magic_w as u64)) % MOD64;
        }
        // println!("p={}, q={}", p, q);
        let x = ((p + q + (magic_b0 as u64)) % MOD64) as u32;
        let mut power = 1u64;
        for k in 0..POW_ACCESSES as usize {
            let term = ((power * (magic_c[k] as u64)) % MOD64) as u32;
            power = (power * (x as u64)) % MOD64;
            magic_mix[i] = (magic_mix[i] + term) % MOD;
        }
    }

    let mut reduction: u32 = 0;
    for i in 0..POW_ACCESSES as usize {
        reduction = reduction.wrapping_mul(FNV_PRIME) ^ magic_mix[i];
    }
    buf.magic_mix = reduction;

    let _mix_hash = buf.compress_bytes;

    let value: H256 = {
        // We can interpret the buffer as an array of `u8`s, since it's
        // `repr(C)`.
        let read_ptr: *const u8 = &buf as *const MixBuf as *const u8;
        let buffer = unsafe {
            core::slice::from_raw_parts(
                read_ptr,
                buf.half_mix.bytes.len() + buf.compress_bytes.len() + 4,
            )
        };
        // We overwrite the buf.compress_bytes since `keccak_256` has an
        // internal buffer and so allows overlapping arrays as input.
        keccak_256::write(buffer, &mut buf.compress_bytes);

        buf.compress_bytes
    };

    value
}

pub fn calculate_dag_item(node_index: u32, cache: &[Node]) -> Node {
    let num_parent_nodes = cache.len();
    let mut ret = cache[node_index as usize % num_parent_nodes].clone();
    ret.as_words_mut()[0] ^= node_index;

    let mut tmp = [0u8; NODE_BYTES];
    keccak_512::write(ret.as_bytes(), &mut tmp);
    ret.as_bytes_mut().copy_from_slice(&tmp);

    debug_assert_eq!(NODE_WORDS, 16);
    for i in 0..POW_DATASET_PARENTS as u32 {
        let parent_index =
            fnv_hash(node_index ^ i, ret.as_words()[i as usize % NODE_WORDS])
                % num_parent_nodes as u32;
        let parent = &cache[parent_index as usize];

        for (a, b) in ret.as_words_mut().iter_mut().zip(parent.as_words()) {
            *a = fnv_hash(*a, *b);
        }
    }

    keccak_512::write(ret.as_bytes(), &mut tmp);
    ret.as_bytes_mut().copy_from_slice(&tmp);

    ret
}
