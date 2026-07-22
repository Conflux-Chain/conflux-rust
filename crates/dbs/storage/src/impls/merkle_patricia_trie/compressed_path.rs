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

    fn as_ref(&self) -> CompressedPathRef<'_> {
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
    use rlp::{Decodable, Rlp, RlpStream};

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

    /// RLP-encode a raw `(mask, slice)` pair, bypassing the constructors so
    /// tests can craft over-long / malformed inputs they can't produce.
    fn encode_path(path_mask: u8, path_slice: &[u8]) -> Vec<u8> {
        let mut s = RlpStream::new_list(2);
        s.append(&path_mask);
        s.append(&path_slice);
        s.out().to_vec()
    }

    fn decode_path(bytes: &[u8]) -> Result<CompressedPathRaw, DecoderError> {
        CompressedPathRaw::decode(&Rlp::new(bytes))
    }

    #[test]
    fn test_decode_normal_path_roundtrips() {
        let slice = vec![0xabu8; 32];
        let bytes = encode_path(CompressedPathRaw::NO_MISSING_NIBBLE, &slice);
        let decoded = decode_path(&bytes).expect("valid path decodes");
        assert_eq!(decoded.path_slice(), slice.as_slice());
    }

    #[test]
    fn test_decode_path_at_cap_is_accepted_without_truncation() {
        let slice = vec![0u8; CompressedPathRaw::MAX_PATH_BYTES];
        let bytes = encode_path(CompressedPathRaw::NO_MISSING_NIBBLE, &slice);
        let decoded = decode_path(&bytes).expect("path at cap decodes");
        assert_eq!(
            decoded.path_slice().len(),
            CompressedPathRaw::MAX_PATH_BYTES
        );
    }

    #[test]
    fn test_decode_over_cap_path_is_rejected() {
        let slice = vec![0u8; CompressedPathRaw::MAX_PATH_BYTES + 1];
        let bytes = encode_path(CompressedPathRaw::NO_MISSING_NIBBLE, &slice);
        assert!(decode_path(&bytes).is_err());
    }

    #[test]
    fn test_decode_mask_handling() {
        // Empty slice + non-zero mask underflows path_steps()/walk(); reject.
        let bytes = encode_path(CompressedPathRaw::second_nibble_mask(), &[]);
        assert!(decode_path(&bytes).is_err());

        let bytes = encode_path(CompressedPathRaw::NO_MISSING_NIBBLE, &[]);
        assert!(decode_path(&bytes).is_ok());

        // The empty-only restriction must not reject a non-empty masked path.
        let bytes = encode_path(0xff, &[1u8]);
        assert!(decode_path(&bytes).is_ok());
    }

    #[test]
    fn test_path_steps_at_cap_does_not_overflow() {
        let path = CompressedPathRaw::new_zeroed(
            CompressedPathRaw::MAX_PATH_BYTES as u16,
            CompressedPathRaw::NO_MISSING_NIBBLE,
        );
        assert_eq!(
            path.path_steps(),
            (CompressedPathRaw::MAX_PATH_BYTES as u16) * 2
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
    /// Maximum bytes in a compressed path / MPT key.
    ///
    /// A byte is two nibbles and `path_steps()` (the nibble count) is a `u16`,
    /// so a path longer than `u16::MAX / 2` overflows `path_size * 2` in
    /// [`Self::calculate_path_steps`]; one over 65535 bytes also truncates the
    /// `u16` `path_size`, making `Drop` free a `Layout` it never allocated
    /// (UB). Such a path can't exist in a validly-built snapshot anyway — its
    /// merkle would overflow `path_steps` on the honest builder — so capping
    /// the receive path rejects only malformed input, not the tens-of-bytes
    /// keys real state uses.
    pub const MAX_PATH_BYTES: usize = (u16::MAX / 2) as usize;
    pub const NO_MISSING_NIBBLE: u8 = 0;

    /// Validate an untrusted `(path_size, path_mask)` before it reaches the
    /// path machinery. Used by both [`CompressedPathRaw`] decoders (RLP,
    /// serde).
    fn check_path_encoding(
        path_size: usize, path_mask: u8,
    ) -> Result<(), &'static str> {
        if path_size > Self::MAX_PATH_BYTES {
            return Err("CompressedPathRaw path too long");
        }
        // An empty path has no nibble, so a non-zero begin/end mask makes
        // `calculate_path_steps`/`walk` compute `0 - 1` and panic.
        if path_size == 0 && path_mask != Self::NO_MISSING_NIBBLE {
            return Err("CompressedPathRaw empty path with non-zero mask");
        }
        Ok(())
    }
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
        if path_size > 0 {
            // 0xf* -> no second nibble
            // 0x0* -> has second nibble
            // 0xf0 -> 0x0f -> &= 0xf0
            // 0x00 -> 0xff -> &= 0xff
            *ret.last_byte_mut() &= !Self::first_nibble(path_mask);
        }

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
            // TODO: resolve warnings in unsafe code.
            #[allow(clippy::uninit_vec)]
            unsafe {
                if size > MaybeInPlaceByteArray::MAX_INPLACE_SIZE {
                    // Create uninitialized vector.
                    let mut value = Vec::with_capacity(size);
                    value.set_len(size);
                    let mut value_box = value.into_boxed_slice();

                    let ptr = value_box.as_mut_ptr();
                    // Don't free the buffer since it's stored in the return
                    // value.
                    let _ = Box::into_raw(value_box);
                    path = MaybeInPlaceByteArray { ptr };
                    slice = std::slice::from_raw_parts_mut(ptr, size);
                } else {
                    let in_place: [u8;
                        MaybeInPlaceByteArray::MAX_INPLACE_SIZE] =
                        Default::default();
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
        let path_mask = rlp.val_at::<u8>(0)?;
        let path_slice = rlp.val_at::<Vec<u8>>(1)?;
        Self::check_path_encoding(path_slice.len(), path_mask)
            .map_err(DecoderError::Custom)?;
        Ok(CompressedPathRaw::new(path_slice.as_slice(), path_mask))
    }
}

impl Serialize for CompressedPathRaw {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let path_mask = self.path_mask();
        let path_mask = format!("0x{:x}", path_mask);
        let path_slice = self.path_slice();
        let mut struc = serializer.serialize_struct("CompressedPathRaw", 2)?;
        struc.serialize_field("pathMask", &path_mask)?;
        struc.serialize_field(
            "pathSlice",
            &("0x".to_owned() + path_slice.to_hex::<String>().as_ref()),
        )?;

        struc.end()
    }
}

impl<'a> Deserialize<'a> for CompressedPathRaw {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'a> {
        let (path_mask, path_slice) = deserializer.deserialize_struct(
            "CompressedPathRaw",
            FIELDS,
            CompressedPathRawVisitor,
        )?;

        Self::check_path_encoding(path_slice.len(), path_mask)
            .map_err(de::Error::custom)?;
        Ok(CompressedPathRaw::new(&path_slice[..], path_mask))
    }
}

const FIELDS: &'static [&'static str] = &["pathMask", "pathSlice"];

enum Field {
    Mask,
    Slice,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
    where D: Deserializer<'de> {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("`pathMask` or `pathSlice`")
            }

            fn visit_str<E>(self, value: &str) -> Result<Field, E>
            where E: de::Error {
                match value {
                    "pathMask" => Ok(Field::Mask),
                    "pathSlice" => Ok(Field::Slice),
                    _ => Err(de::Error::unknown_field(value, FIELDS)),
                }
            }
        }

        deserializer.deserialize_identifier(FieldVisitor)
    }
}

struct CompressedPathRawVisitor;
impl<'a> Visitor<'a> for CompressedPathRawVisitor {
    type Value = (u8, Vec<u8>);

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Struct CompressedPath")
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where V: MapAccess<'a> {
        let mut path_mask = None;
        let mut path_slice = None;

        while let Some(key) = visitor.next_key()? {
            match key {
                Field::Mask => {
                    if path_mask.is_some() {
                        return Err(de::Error::duplicate_field("pathMask"));
                    }

                    path_mask = Some(visitor.next_value()?);
                }
                Field::Slice => {
                    if path_slice.is_some() {
                        return Err(de::Error::duplicate_field("pathSlice"));
                    }

                    path_slice = Some(visitor.next_value()?);
                }
            }
        }

        let path_mask: String =
            path_mask.ok_or_else(|| de::Error::missing_field("pathMask"))?;

        let path_mask = if let Some(s) = path_mask.strip_prefix("0x") {
            u8::from_str_radix(&s, 16).map_err(|e| {
                de::Error::custom(format!("pathMask: invalid hex: {}", e))
            })?
        } else {
            return Err(de::Error::custom(
                "pathMask: invalid format. Expected a 0x-prefixed hex string",
            ));
        };

        let path_slice: String =
            path_slice.ok_or_else(|| de::Error::missing_field("pathSlice"))?;

        let path_slice: Vec<u8> = if let (Some(s), true) =
            (path_slice.strip_prefix("0x"), path_slice.len() & 1 == 0)
        {
            FromHex::from_hex(s).map_err(|e| {
                de::Error::custom(format!("pathSlice: invalid hex: {}", e))
            })?
        } else {
            return Err(de::Error::custom("pathSlice: invalid format. Expected a 0x-prefixed hex string with even length"));
        };

        Ok((path_mask, path_slice))
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
use rustc_hex::{FromHex, ToHex};
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};

use std::{
    borrow::Borrow,
    fmt::{self, Debug, Error, Formatter},
    hash::{Hash, Hasher},
    result::Result,
};
