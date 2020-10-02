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
const POW_MOD64: u64 = POW_MOD as u64;

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

fn fnv_hash64(x: u64, y: u64) -> u64 {
    return x.wrapping_mul(FNV_PRIME as u64) ^ y;
}

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

#[allow(dead_code)]
fn as_u32_le(bytes: &[u8]) -> u32 {
    assert!(bytes.len() == 4);

    ((bytes[0] as u32) << 0)
        + ((bytes[1] as u32) << 8)
        + ((bytes[2] as u32) << 16)
        + ((bytes[3] as u32) << 24)
}

fn as_u64_le(bytes: &[u8]) -> u64 {
    assert!(bytes.len() == 8);

    ((bytes[0] as u64) << 0)
        + ((bytes[1] as u64) << 8)
        + ((bytes[2] as u64) << 16)
        + ((bytes[3] as u64) << 24)
        + ((bytes[4] as u64) << 32)
        + ((bytes[5] as u64) << 40)
        + ((bytes[6] as u64) << 48)
        + ((bytes[7] as u64) << 56)
}

fn rotl(x: u64, b: u64) -> u64 { (x << b) | (x >> (64 - b)) }

struct SipHasher {
    pub v0: u64,
    pub v1: u64,
    pub v2: u64,
    pub v3: u64,
}

impl SipHasher {
    pub fn new(v0: u64, v1: u64, v2: u64, v3: u64) -> Self {
        SipHasher { v0, v1, v2, v3 }
    }

    pub fn xor_lanes(&self) -> u64 { self.v0 ^ self.v1 ^ self.v2 ^ self.v3 }

    pub fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v1 = rotl(self.v1, 13);
        self.v3 = rotl(self.v3, 16);
        self.v1 ^= self.v0;
        self.v3 ^= self.v2;
        self.v0 = rotl(self.v0, 32);
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v1 = rotl(self.v1, 17);
        self.v3 = rotl(self.v3, 21);
        self.v1 ^= self.v2;
        self.v3 ^= self.v0;
        self.v2 = rotl(self.v2, 32);
    }

    pub fn hash24(&mut self, nonce: u64) {
        self.v3 ^= nonce;
        self.sip_round();
        self.sip_round();
        self.v0 ^= nonce;
        self.v2 ^= 0xff;
        self.sip_round();
        self.sip_round();
        self.sip_round();
        self.sip_round();
    }
}

fn hash_compute(
    light: &Light, full_size: usize, header_hash: &H256, nonce: u64,
) -> H256 {
    let v0 = as_u64_le(&header_hash[0..8]);
    let v1 = as_u64_le(&header_hash[8..16]);
    let v2 = as_u64_le(&header_hash[16..24]);
    let v3 = as_u64_le(&header_hash[24..32]);
    let mut d: [u32; POW_N as usize] = [0; POW_N as usize];

    fn remap(h: u64) -> u64 {
        fn power_mod(a1: u32, n0: u64) -> u64 {
            let mut a = a1 as u64;
            let mut n = n0;
            let mut result = 1u64;
            while n > 0 {
                if n % 2 == 1 {
                    result = result * a % POW_MOD64;
                }
                a = a * a % POW_MOD64;
                n >>= 1;
            }
            return result;
        }

        fn gcd(a: u64, b: u64) -> u64 {
            if b == 0 {
                return a;
            } else {
                return gcd(b, a % b);
            }
        }

        let mut e = h % (POW_MOD64 - 2) + 1;
        loop {
            let g = gcd(e, POW_MOD64 - 1);
            if g == 1 {
                break;
            }
            e /= g
        }
        return power_mod(POW_MOD_B, e) as u64;
    }

    fn compute_c(a: u64, b: u64, h0: u64) -> u64 {
        let mut h = h0;
        loop {
            let c = remap(h);
            if b * b % POW_MOD64 != 4u64 * a * c % POW_MOD64 {
                return c;
            }
            h = h.wrapping_add(1);
        }
    }

    let a = remap(v0);
    let b = remap(v1);
    let c = compute_c(a, b, v2);
    let w = remap(v3);

    let warp_id = nonce / POW_WARP_SIZE;
    for i in 0..POW_WARP_SIZE {
        let mut hasher = SipHasher::new(v0, v1, v2, v3);
        hasher.hash24(warp_id * POW_WARP_SIZE + i as u64);
        for j in 0..POW_DATA_PER_THREAD {
            hasher.sip_round();
            d[(j * POW_WARP_SIZE + i) as usize] =
                ((hasher.xor_lanes() & (u32::MAX as u64)) % POW_MOD64) as u32;
        }
    }

    let w2 = (w as u64) * (w as u64) % POW_MOD64;
    let mut wpow = 1u64;
    let mut w2pow = 1u64;

    for _ in 0..nonce % POW_WARP_SIZE {
        wpow = wpow * (w as u64) % POW_MOD64;
        w2pow = w2pow * w2 % POW_MOD64;
    }
    let mut full_wpow = wpow;
    let mut full_w2pow = w2pow;
    for _ in nonce % POW_WARP_SIZE..POW_WARP_SIZE {
        full_wpow = full_wpow * (w as u64) % POW_MOD64;
        full_w2pow = full_w2pow * w2 % POW_MOD64;
    }

    let mut res_buf = [0 as u32; POW_DATA_PER_THREAD as usize];
    let mut result = 0;
    for i in 0..POW_DATA_PER_THREAD {
        let x = (a * w2pow + b * wpow + c) % POW_MOD64;
        let mut pv = 0;
        for j in 0..POW_N {
            pv = (pv * x + d[(POW_N - j - 1) as usize] as u64) % POW_MOD64;
        }
        res_buf[i as usize] = pv as u32;
        result = fnv_hash64(result, pv);
        if i + 1 < POW_DATA_PER_THREAD {
            wpow = wpow * full_wpow % POW_MOD64;
            w2pow = w2pow * full_w2pow % POW_MOD64;
        }
    }

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
        compress_bytes: [u8; 32],
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
            out[hash_len..end].copy_from_slice(&result.to_ne_bytes());
            // let end = nonce_end + mem::size_of::<u64>();
            // out[nonce_end..end].copy_from_slice(&result.to_ne_bytes());

            // compute keccak-512 hash and replicate across mix
            let mut tmp = [0u8; NODE_BYTES];
            keccak_512::write(&out[0..end], &mut tmp);
            out.copy_from_slice(&tmp);

            Node { bytes: out }
        },
        compress_bytes: [0u8; 32],
    };

    let mut mix: [_; MIX_NODES] = [
        buf.half_mix.clone(),
        buf.half_mix.clone(),
        buf.half_mix.clone(),
        buf.half_mix.clone(),
    ];

    let page_size = 4 * MIX_WORDS;
    let num_full_pages = (full_size / page_size) as u32;
    // deref once for better performance
    let cache: &[Node] = light.cache.as_ref();
    let first_val = buf.half_mix.as_words()[0];

    debug_assert_eq!(MIX_NODES, 4);
    debug_assert_eq!(NODE_WORDS, 16);

    for i in 0..POW_ACCESSES as u32 {
        let index = {
            // This is trivially safe, but does not work on big-endian. The
            // safety of this is asserted in debug builds (see the
            // definition of `make_const_array!`).
            let mix_words: &mut [u32; MIX_WORDS] =
                unsafe { make_const_array!(MIX_WORDS, &mut mix) };

            fnv_hash(
                first_val ^ i ^ res_buf[i as usize],
                mix_words[i as usize % MIX_WORDS],
            ) % num_full_pages
        };

        // MIX_NODES
        for n in 0..MIX_NODES {
            let tmp_node =
                calculate_dag_item(index * MIX_NODES as u32 + n as u32, cache);

            // NODE_WORDS
            for (a, b) in
                mix[n].as_words_mut().iter_mut().zip(tmp_node.as_words())
            {
                *a = fnv_hash(*a, *b);
            }
        }
    }

    let mix_words: [u32; MIX_WORDS] = unsafe { mem::transmute(mix) };

    {
        // We iterate precisely `compress.len()` times and set each index,
        // leaving the array fully initialized. THIS ONLY WORKS ON LITTLE-ENDIAN
        // MACHINES. See a future PR to make this and the rest of the
        // code work correctly on big-endian arches like mips.
        let compress: &mut [u32; 8] =
            unsafe { make_const_array!(8, &mut buf.compress_bytes) };

        // Compress mix
        for i in 0..8 {
            let w = i * 4;
            let w2 = (8 + i) * 4;

            let mut reduction = mix_words[w + 0];
            reduction = reduction.wrapping_mul(FNV_PRIME) ^ mix_words[w + 1];
            reduction = reduction.wrapping_mul(FNV_PRIME) ^ mix_words[w + 2];
            reduction = reduction.wrapping_mul(FNV_PRIME) ^ mix_words[w + 3];

            let mut reduction2 = mix_words[w2 + 0];
            reduction2 = reduction2.wrapping_mul(FNV_PRIME) ^ mix_words[w2 + 1];
            reduction2 = reduction2.wrapping_mul(FNV_PRIME) ^ mix_words[w2 + 2];
            reduction2 = reduction2.wrapping_mul(FNV_PRIME) ^ mix_words[w2 + 3];

            compress[i] = reduction.wrapping_mul(FNV_PRIME) ^ reduction2;
        }
    }

    let _mix_hash = buf.compress_bytes;

    let value: H256 = {
        // We can interpret the buffer as an array of `u8`s, since it's
        // `repr(C)`.
        let read_ptr: *const u8 = &buf as *const MixBuf as *const u8;
        let buffer = unsafe {
            core::slice::from_raw_parts(
                read_ptr,
                buf.half_mix.bytes.len() + buf.compress_bytes.len(),
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
