use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::ser::SerializeMap;
use serde_derive::{Deserialize, Serialize};
use std::ops::{Add, Index, IndexMut};

#[derive(
    Eq,
    PartialEq,
    Hash,
    Copy,
    Clone,
    Debug,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Space {
    Native,
    #[serde(rename(serialize = "evm", deserialize = "evm"))]
    Ethereum,
}

impl From<Space> for String {
    fn from(space: Space) -> Self {
        let str: &'static str = space.into();
        str.into()
    }
}

impl From<Space> for &'static str {
    fn from(space: Space) -> Self {
        match space {
            Space::Native => "native",
            Space::Ethereum => "evm",
        }
    }
}

impl Encodable for Space {
    fn rlp_append(&self, s: &mut RlpStream) {
        let type_int: u8 = match self {
            Space::Native => 1,
            Space::Ethereum => 2,
        };
        type_int.rlp_append(s)
    }
}

impl Decodable for Space {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match u8::decode(rlp)? {
            1u8 => Ok(Space::Native),
            2u8 => Ok(Space::Ethereum),
            _ => Err(DecoderError::Custom("Unrecognized space byte.")),
        }
    }
}

impl Default for Space {
    fn default() -> Self { Space::Native }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub struct SpaceMap<T> {
    native: T,
    evm: T,
}

impl<T> SpaceMap<T> {
    pub const fn new(native: T, evm: T) -> Self { SpaceMap { native, evm } }

    #[inline]
    pub const fn in_space(&self, space: Space) -> &T {
        match space {
            Space::Native => &self.native,
            Space::Ethereum => &self.evm,
        }
    }

    #[inline]
    pub fn in_space_mut(&mut self, space: Space) -> &mut T {
        match space {
            Space::Native => &mut self.native,
            Space::Ethereum => &mut self.evm,
        }
    }

    pub fn zip3<B, C>(
        a: SpaceMap<T>, b: SpaceMap<B>, c: SpaceMap<C>,
    ) -> SpaceMap<(T, B, C)> {
        SpaceMap {
            native: (a.native, b.native, c.native),
            evm: (a.evm, b.evm, c.evm),
        }
    }

    pub fn zip4<B, C, D>(
        a: SpaceMap<T>, b: SpaceMap<B>, c: SpaceMap<C>, d: SpaceMap<D>,
    ) -> SpaceMap<(T, B, C, D)> {
        SpaceMap {
            native: (a.native, b.native, c.native, d.native),
            evm: (a.evm, b.evm, c.evm, d.evm),
        }
    }

    pub fn map_sum<F: FnMut(&T) -> U, U: Add<U, Output = U>>(
        &self, mut f: F,
    ) -> U {
        f(&self.native) + f(&self.evm)
    }

    pub const fn size(&self) -> usize { 2 }

    pub fn map_all<U, F: Fn(T) -> U>(self, f: F) -> SpaceMap<U> {
        SpaceMap {
            native: f(self.native),
            evm: f(self.evm),
        }
    }

    pub fn apply_all<U, F: FnMut(&mut T) -> U>(
        &mut self, mut f: F,
    ) -> SpaceMap<U> {
        SpaceMap {
            native: f(&mut self.native),
            evm: f(&mut self.evm),
        }
    }
}

impl<T> Index<Space> for SpaceMap<T> {
    type Output = T;

    fn index(&self, space: Space) -> &Self::Output { self.in_space(space) }
}

impl<T> IndexMut<Space> for SpaceMap<T> {
    fn index_mut(&mut self, space: Space) -> &mut Self::Output {
        self.in_space_mut(space)
    }
}

impl<T: serde::Serialize> serde::Serialize for SpaceMap<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        let mut map = serializer.serialize_map(Some(self.size()))?;
        map.serialize_entry("core", &self.native)?;
        map.serialize_entry("espace", &self.evm)?;
        map.end()
    }
}
