// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait CompressedPathTrait {
    type SelfType;

    fn path_slice(&self) -> &[u8];
    fn end_mask(&self) -> u8;
}

impl<'a> CompressedPathTrait for &'a [u8] {
    type SelfType = Self;

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
    pub(super) path_size: u16,
    pub(super) path: MaybeInPlaceByteArray,
    end_mask: u8,
}

impl CompressedPathRaw {
    const BITS_0_3_MASK: u8 = 0x0f;
    const BITS_4_7_MASK: u8 = 0xf0;
}

impl<'a> CompressedPathTrait for CompressedPathRef<'a> {
    type SelfType = Self;

    fn path_slice(&self) -> &[u8] { self.path_slice }

    fn end_mask(&self) -> u8 { self.end_mask }
}

impl CompressedPathTrait for CompressedPathRaw {
    type SelfType = Self;

    fn path_slice(&self) -> &[u8] {
        self.path.get_slice(self.path_size as usize)
    }

    fn end_mask(&self) -> u8 { self.end_mask }
}

impl<'a> From<&'a [u8]> for CompressedPathRaw {
    fn from(x: &'a [u8]) -> Self { CompressedPathRaw::new(x, 0) }
}

impl CompressedPathRaw {
    pub fn new(path_slice: &[u8], end_mask: u8) -> Self {
        let path_size = path_slice.len();
        Self {
            path_size: path_size as u16,
            path: MaybeInPlaceByteArray::copy_from(path_slice, path_size),
            end_mask,
        }
    }

    pub fn new_and_apply_mask(path_slice: &[u8], end_mask: u8) -> Self {
        let path_size = path_slice.len();
        let mut ret = Self {
            path_size: path_size as u16,
            path: MaybeInPlaceByteArray::copy_from(path_slice, path_size),
            end_mask,
        };
        ret.path.get_slice_mut(path_size)[path_size - 1] &= end_mask;

        ret
    }

    pub fn new_zeroed(path_size: u16, end_mask: u8) -> Self {
        Self {
            path_size,
            path: MaybeInPlaceByteArray::new_zeroed(path_size as usize),
            end_mask,
        }
    }

    pub fn first_nibble(x: u8) -> u8 { x & Self::BITS_0_3_MASK }

    pub fn second_nibble(x: u8) -> u8 { (x & Self::BITS_4_7_MASK) >> 4 }

    pub fn set_second_nibble(x: u8, second_nibble: u8) -> u8 {
        Self::first_nibble(x) | (second_nibble << 4)
    }
}

impl<'a> CompressedPathRef<'a> {
    // TODO(yz): the format can be optimized.
    pub fn rlp_append_parts(&self, s: &mut RlpStream) {
        s.append(&self.end_mask).append(&self.path_slice);
    }
}

impl<'a> Encodable for CompressedPathRef<'a> {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        self.rlp_append_parts(s);
    }
}

impl Decodable for CompressedPathRaw {
    // TODO(yz): the format can be optimized.
    fn decode(rlp: &Rlp) -> ::std::result::Result<Self, DecoderError> {
        Ok(CompressedPathRaw::new(
            rlp.val_at::<Vec<u8>>(1)?.as_slice(),
            rlp.val_at(0)?,
        ))
    }
}

impl CompressedPathRaw {
    pub fn concat<X: CompressedPathTrait, Y: CompressedPathTrait>(
        x: &X, child_index: u8, y: &Y,
    ) -> Self {
        let x_slice = x.path_slice();
        let y_slice = y.path_slice();
        let size = x_slice.len() + y_slice.len();

        let mut path;
        if size <= MaybeInPlaceByteArray::MAX_INPLACE_SIZE {
            path = MaybeInPlaceByteArray::copy_from(x_slice, x_slice.len());
            path.get_slice_mut(size)
                [x_slice.len()..x_slice.len() + y_slice.len()]
                .clone_from_slice(y_slice);
        } else {
            path = MaybeInPlaceByteArray::copy_from(
                &([x_slice, y_slice].concat()),
                size,
            );
        }

        if x.end_mask() != 0 {
            let path_slice_mut = path.get_slice_mut(size);
            path_slice_mut[x_slice.len() - 1] =
                CompressedPathRaw::set_second_nibble(
                    path_slice_mut[x_slice.len() - 1],
                    child_index,
                );
        }

        Self {
            path_size: size as u16,
            path,
            end_mask: y.end_mask(),
        }
    }
}

use super::maybe_in_place_byte_array::MaybeInPlaceByteArray;
use rlp::*;
