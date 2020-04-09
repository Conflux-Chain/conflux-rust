// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait CompressedPathTrait: Debug {
    fn path_slice(&self) -> &[u8];
    fn path_mask(&self) -> u8;

    fn path_size(&self) -> u16 { self.path_slice().len() as u16 }

    fn path_steps(&self) -> u16 {
        CompressedPathRaw::calculate_path_steps(
            self.path_size(),
            self.path_mask(),
        )
    }

    fn as_ref(&self) -> CompressedPathRef {
        CompressedPathRef {
            path_slice: self.path_slice(),
            path_mask: self.path_mask(),
        }
    }

    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.path_mask()).append(&self.path_slice());
    }
}

impl CompressedPathTrait for [u8] {
    fn path_slice(&self) -> &[u8] { self }

    fn path_mask(&self) -> u8 { CompressedPathRaw::NO_MISSING_NIBBLE }
}

impl<'a> CompressedPathTrait for &'a [u8] {
    fn path_slice(&self) -> &[u8] { self }

    fn path_mask(&self) -> u8 { CompressedPathRaw::NO_MISSING_NIBBLE }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CompressedPathRef<'a> {
    pub path_slice: &'a [u8],
    path_mask: u8,
}

impl<'a> CompressedPathRef<'a> {
    pub fn new(path_slice: &'a [u8], path_mask: u8) -> Self {
        Self {
            path_slice,
            path_mask,
        }
    }
}

#[derive(Default)]
pub struct CompressedPathRaw {
    path_size: u16,
    path: MaybeInPlaceByteArray,
    path_mask: u8,
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
    pub const NO_MISSING_NIBBLE: u8 = 0;
}

impl<'a> CompressedPathTrait for CompressedPathRef<'a> {
    fn path_slice(&self) -> &[u8] { self.path_slice }

    fn path_mask(&self) -> u8 { self.path_mask }

    fn path_size(&self) -> u16 { self.path_slice.len() as u16 }
}

impl CompressedPathTrait for CompressedPathRaw {
    fn path_slice(&self) -> &[u8] {
        self.path.get_slice(self.path_size as usize)
    }

    fn path_mask(&self) -> u8 { self.path_mask }
}

impl<'a> From<&'a [u8]> for CompressedPathRaw {
    fn from(x: &'a [u8]) -> Self {
        CompressedPathRaw::new(x, Self::NO_MISSING_NIBBLE)
    }
}

impl<'a> From<CompressedPathRef<'a>> for CompressedPathRaw {
    fn from(x: CompressedPathRef<'a>) -> Self {
        CompressedPathRaw::new(x.path_slice, x.path_mask)
    }
}

impl CompressedPathRaw {
    /// Create a new CompressedPathRaw from valid (path_slice, path_mask)
    /// combination.
    pub fn new(path_slice: &[u8], path_mask: u8) -> Self {
        let path_size = path_slice.len();

        Self {
            path_size: path_size as u16,
            path: MaybeInPlaceByteArray::copy_from(path_slice, path_size),
            path_mask,
            byte_array_memory_manager: Default::default(),
        }
    }

    #[inline]
    fn last_byte_mut(&mut self) -> &mut u8 {
        // Safe, because the index is valid.
        unsafe {
            self.path
                .get_slice_mut(self.path_size as usize)
                .get_unchecked_mut(self.path_size as usize - 1)
        }
    }

    pub fn new_and_apply_mask(path_slice: &[u8], path_mask: u8) -> Self {
        let path_size = path_slice.len();
        let mut ret = Self {
            path_size: path_size as u16,
            path: MaybeInPlaceByteArray::copy_from(path_slice, path_size),
            path_mask,
            byte_array_memory_manager: Default::default(),
        };
        // 0xf* -> no second nibble
        // 0x0* -> has second nibble
        // 0xf0 -> 0x0f -> &= 0xf0
        // 0x00 -> 0xff -> &= 0xff
        *ret.last_byte_mut() &= !Self::first_nibble(path_mask);

        ret
    }

    pub fn new_zeroed(path_size: u16, path_mask: u8) -> Self {
        Self {
            path_size,
            path: MaybeInPlaceByteArray::new_zeroed(path_size as usize),
            path_mask,
            byte_array_memory_manager: Default::default(),
        }
    }

    #[inline]
    pub const fn first_nibble_mask() -> u8 { Self::BITS_0_3_MASK }

    #[inline]
    pub const fn second_nibble_mask() -> u8 { Self::BITS_4_7_MASK }

    #[inline]
    fn calculate_path_steps(path_size: u16, path_mask: u8) -> u16 {
        path_size * 2
            - (Self::clear_second_nibble(path_mask) != 0) as u16
            - (Self::second_nibble(path_mask) != 0) as u16
    }

    #[inline]
    pub fn from_first_nibble(x: u8) -> u8 { x << 4 }

    #[inline]
    pub fn first_nibble(x: u8) -> u8 { x >> 4 }

    #[inline]
    pub fn clear_second_nibble(x: u8) -> u8 { x & Self::BITS_4_7_MASK }

    #[inline]
    pub fn second_nibble(x: u8) -> u8 { x & Self::BITS_0_3_MASK }

    #[inline]
    pub fn set_second_nibble(x: u8, second_nibble: u8) -> u8 {
        Self::clear_second_nibble(x) | second_nibble
    }

    #[inline]
    pub fn has_second_nibble(path_mask: u8) -> bool {
        Self::clear_second_nibble(path_mask)
            == CompressedPathRaw::NO_MISSING_NIBBLE
    }

    #[inline]
    pub fn no_second_nibble(path_mask: u8) -> bool {
        Self::clear_second_nibble(path_mask)
            != CompressedPathRaw::NO_MISSING_NIBBLE
    }

    pub fn extend_path<X: CompressedPathTrait>(x: &X, child_index: u8) -> Self {
        let new_size;
        let path_mask;
        // Need to extend the length.
        let x_path_mask = x.path_mask();
        if Self::has_second_nibble(x_path_mask) {
            new_size = x.path_size() + 1;
            path_mask = x_path_mask | Self::second_nibble_mask();
        } else {
            new_size = x.path_size();
            path_mask = Self::second_nibble(x_path_mask);
        }
        let mut ret = Self::new_zeroed(new_size, path_mask);
        ret.path.get_slice_mut(new_size as usize)[0..x.path_size() as usize]
            .copy_from_slice(x.path_slice());
        // The last byte will be a half-byte.
        if Self::has_second_nibble(x_path_mask) {
            *ret.last_byte_mut() = Self::from_first_nibble(child_index);
        } else {
            let last_byte = *ret.last_byte_mut();
            *ret.last_byte_mut() =
                Self::set_second_nibble(last_byte, child_index);
        }

        ret
    }

    /// y must be a valid path following x. i.e. when x ends with a full byte, y
    /// must be non-empty and start with nibble child_index.
    pub fn join_connected_paths<
        X: CompressedPathTrait,
        Y: CompressedPathTrait,
    >(
        x: &X, child_index: u8, y: &Y,
    ) -> Self {
        let x_slice = x.path_slice();
        let x_slice_len = x_slice.len();
        let x_path_mask = x.path_mask();
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
                    let mut value_box = value.into_boxed_slice();

                    let ptr = value_box.as_mut_ptr();
                    // Don't free the buffer since it's stored in the return
                    // value.
                    Box::into_raw(value_box);
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

            if Self::has_second_nibble(x_path_mask) {
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
            path_mask: Self::set_second_nibble(
                y.path_mask(),
                CompressedPathRaw::second_nibble(x_path_mask),
            ),
            byte_array_memory_manager: Default::default(),
        }
    }
}

impl Clone for CompressedPathRaw {
    fn clone(&self) -> Self {
        Self {
            path_mask: self.path_mask,
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

impl Eq for CompressedPathRaw {}

impl Hash for CompressedPathRaw {
    fn hash<H: Hasher>(&self, state: &mut H) { self.as_ref().hash(state) }
}

impl Debug for CompressedPathRaw {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        self.as_ref().fmt(f)
    }
}

impl CompressedPathRaw {
    pub fn path_slice_mut(&mut self) -> &mut [u8] {
        self.path.get_slice_mut(self.path_size as usize)
    }
}

impl<'a> PartialEq<Self> for dyn CompressedPathTrait + 'a {
    fn eq(&self, other: &(dyn CompressedPathTrait + 'a)) -> bool {
        self.as_ref().eq(&other.as_ref())
    }
}

impl<'a> Eq for dyn CompressedPathTrait + 'a {}

impl<'a> Hash for dyn CompressedPathTrait + 'a {
    fn hash<H: Hasher>(&self, state: &mut H) { self.as_ref().hash(state) }
}

impl<'a> Borrow<dyn CompressedPathTrait + 'a> for CompressedPathRaw {
    fn borrow(&self) -> &(dyn CompressedPathTrait + 'a) { self }
}

use super::maybe_in_place_byte_array::*;
use rlp::*;
use std::{
    borrow::Borrow,
    fmt::{Debug, Error, Formatter},
    hash::{Hash, Hasher},
    result::Result,
};
