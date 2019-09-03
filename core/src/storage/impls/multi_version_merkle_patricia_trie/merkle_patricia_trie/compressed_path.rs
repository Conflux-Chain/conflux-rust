// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait CompressedPathTrait {
    fn path_slice(&self) -> &[u8];
    fn end_mask(&self) -> u8;

    fn path_size(&self) -> u16 { self.path_slice().len() as u16 }

    fn path_steps(&self) -> u16 {
        self.path_size() * 2 - (self.end_mask() != 0) as u16
    }

    // TODO(yz): the format can be optimized to save 1 or 2 bytes: a string with
    // 0 prefix means path_slice with even length, a string with 1 prefix
    // means path_slice with odd length.
    fn rlp_append_parts(&self, s: &mut RlpStream) {
        s.append(&self.end_mask()).append(&self.path_slice());
    }

    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        self.rlp_append_parts(s);
    }
}

impl<'a> CompressedPathTrait for &'a [u8] {
    fn path_slice(&self) -> &[u8] { self }

    fn end_mask(&self) -> u8 { 0 }
}

#[derive(Debug, PartialEq)]
pub struct CompressedPathRef<'a> {
    pub(super) path_slice: &'a [u8],
    pub(super) end_mask: u8,
}

#[derive(Default)]
pub struct CompressedPathRaw {
    path_size: u16,
    path: MaybeInPlaceByteArray,
    end_mask: u8,
    pub byte_array_memory_manager:
        FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
            u16,
            TrivialSizeFieldConverterU16,
            CompressedPathRawByteArrayMemoryManager,
            CompressedPathRawByteArrayMemoryManager,
        >,
}

/// CompressedPathRaw is Send + Sync.
unsafe impl Send for CompressedPathRaw {}
unsafe impl Sync for CompressedPathRaw {}

#[cfg(test)]
mod tests {
    use super::{super::maybe_in_place_byte_array::*, *};

    #[test]
    fn test_compressed_path_raw_memory_manager_size() {
        assert_eq!(
            std::mem::size_of::<
                FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
                    u16,
                    TrivialSizeFieldConverterU16,
                    CompressedPathRawByteArrayMemoryManager,
                    CompressedPathRawByteArrayMemoryManager,
                >,
            >(),
            0
        );
    }
}

make_parallel_field_maybe_in_place_byte_array_memory_manager!(
    CompressedPathRawByteArrayMemoryManager,
    CompressedPathRaw,
    byte_array_memory_manager,
    path,
    path_size: u16,
    TrivialSizeFieldConverterU16,
);

impl CompressedPathRaw {
    const BITS_0_3_MASK: u8 = 0x0f;
    const BITS_4_7_MASK: u8 = 0xf0;
}

impl<'a> CompressedPathTrait for CompressedPathRef<'a> {
    fn path_slice(&self) -> &[u8] { self.path_slice }

    fn end_mask(&self) -> u8 { self.end_mask }

    fn path_size(&self) -> u16 { self.path_slice.len() as u16 }

    fn path_steps(&self) -> u16 {
        (self.path_slice.len() as u16 * 2) - (self.end_mask != 0) as u16
    }
}

impl CompressedPathTrait for CompressedPathRaw {
    fn path_slice(&self) -> &[u8] {
        self.path.get_slice(self.path_size as usize)
    }

    fn end_mask(&self) -> u8 { self.end_mask }
}

impl<'a> From<&'a [u8]> for CompressedPathRaw {
    fn from(x: &'a [u8]) -> Self { CompressedPathRaw::new(x, 0) }
}

impl<'a> From<CompressedPathRef<'a>> for CompressedPathRaw {
    fn from(x: CompressedPathRef<'a>) -> Self {
        CompressedPathRaw::new(x.path_slice, x.end_mask)
    }
}

impl CompressedPathRaw {
    pub fn new(path_slice: &[u8], end_mask: u8) -> Self {
        let path_size = path_slice.len();

        Self {
            path_size: path_size as u16,
            path: MaybeInPlaceByteArray::copy_from(path_slice, path_size),
            end_mask,
            byte_array_memory_manager: Default::default(),
        }
    }

    pub fn new_and_apply_mask(path_slice: &[u8], end_mask: u8) -> Self {
        let path_size = path_slice.len();
        let mut ret = Self {
            path_size: path_size as u16,
            path: MaybeInPlaceByteArray::copy_from(path_slice, path_size),
            end_mask,
            byte_array_memory_manager: Default::default(),
        };
        ret.path.get_slice_mut(path_size)[path_size - 1] &= end_mask;

        ret
    }

    pub fn new_zeroed(path_size: u16, end_mask: u8) -> Self {
        Self {
            path_size,
            path: MaybeInPlaceByteArray::new_zeroed(path_size as usize),
            end_mask,
            byte_array_memory_manager: Default::default(),
        }
    }

    // FIXME: in ethereum the first nibble is (x & Self::BITS_4_7_MASK) >> 4,
    // FIXME: the second nibble.
    pub fn first_nibble(x: u8) -> u8 { x & Self::BITS_0_3_MASK }

    pub fn second_nibble(x: u8) -> u8 { (x & Self::BITS_4_7_MASK) >> 4 }

    pub fn set_second_nibble(x: u8, second_nibble: u8) -> u8 {
        Self::first_nibble(x) | (second_nibble << 4)
    }

    pub fn concat<X: CompressedPathTrait, Y: CompressedPathTrait>(
        x: &X, child_index: u8, y: &Y,
    ) -> Self {
        let x_slice = x.path_slice();
        let x_slice_len = x_slice.len();
        let y_slice = y.path_slice();

        // TODO(yz): it happens to be the same no matter what end_mask of x is,
        // because u8 = 2 nibbles. When we switch to u32 as path unit
        // the concated size may vary.
        let size = x_slice_len + y_slice.len();

        let mut path;
        {
            let slice;
            unsafe {
                if size > MaybeInPlaceByteArray::MAX_INPLACE_SIZE {
                    // Create uninitialized vector.
                    let mut value = Vec::with_capacity(size);
                    value.set_len(size);

                    let ptr = value.as_mut_ptr();
                    path = MaybeInPlaceByteArray { ptr };
                    slice = std::slice::from_raw_parts_mut(ptr, size);
                } else {
                    let in_place: [u8;
                        MaybeInPlaceByteArray::MAX_INPLACE_SIZE] =
                        std::mem::uninitialized();
                    path = MaybeInPlaceByteArray { in_place };
                    slice = &mut path.in_place[0..size];
                }
            }

            if x.end_mask() == 0 {
                slice[0..x_slice_len].copy_from_slice(x_slice);
            } else {
                slice[0..x_slice_len - 1]
                    .copy_from_slice(&x_slice[0..x_slice_len - 1]);
                slice[x_slice_len - 1] = CompressedPathRaw::set_second_nibble(
                    x_slice[x_slice_len - 1],
                    child_index,
                );
            }
            slice[x_slice_len..].copy_from_slice(y_slice);
        }

        Self {
            path_size: size as u16,
            path,
            end_mask: y.end_mask(),
            byte_array_memory_manager: Default::default(),
        }
    }
}

impl Clone for CompressedPathRaw {
    fn clone(&self) -> Self {
        Self {
            end_mask: self.end_mask,
            path_size: self.path_size,
            path: MaybeInPlaceByteArray::clone(
                &self.path,
                self.path_size as usize,
            ),
            byte_array_memory_manager: Default::default(),
        }
    }
}

impl<'a> Encodable for CompressedPathRef<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        CompressedPathTrait::rlp_append(self, s);
    }
}

impl Encodable for CompressedPathRaw {
    fn rlp_append(&self, s: &mut RlpStream) {
        CompressedPathTrait::rlp_append(self, s);
    }
}

impl Decodable for CompressedPathRaw {
    // TODO(yz): the format can be optimized.
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(CompressedPathRaw::new(
            rlp.val_at::<Vec<u8>>(1)?.as_slice(),
            rlp.val_at(0)?,
        ))
    }
}

impl PartialEq<Self> for CompressedPathRaw {
    fn eq(&self, other: &Self) -> bool { self.as_ref().eq(&other.as_ref()) }
}

impl Debug for CompressedPathRaw {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        self.as_ref().fmt(f)
    }
}

impl CompressedPathRaw {
    pub fn as_ref(&self) -> CompressedPathRef {
        CompressedPathRef {
            path_slice: self.path_slice(),
            end_mask: self.end_mask,
        }
    }

    pub fn path_slice_mut(&mut self) -> &mut [u8] {
        self.path.get_slice_mut(self.path_size as usize)
    }
}

use super::maybe_in_place_byte_array::*;
use rlp::*;
use std::{
    fmt::{Debug, Error, Formatter},
    result::Result,
};
