use std::{
    iter::{FromIterator, IntoIterator},
    ops::{BitAnd, BitOr, BitXor, Not},
    usize,
};

use util::*;

use AtomicBitSet;
use BitIter;
use BitSet;
use BitSetLike;
use DrainableBitSet;

/// `BitSetAnd` takes two [`BitSetLike`] items, and merges the masks
/// returning a new virtual set, which represents an intersection of the
/// two original sets.
///
/// [`BitSetLike`]: ../trait.BitSetLike.html
#[derive(Debug)]
pub struct BitSetAnd<A: BitSetLike, B: BitSetLike>(pub A, pub B);

impl<A: BitSetLike, B: BitSetLike> BitSetLike for BitSetAnd<A, B> {
    #[inline]
    fn layer3(&self) -> usize {
        self.0.layer3() & self.1.layer3()
    }

    #[inline]
    fn layer2(&self, i: usize) -> usize {
        self.0.layer2(i) & self.1.layer2(i)
    }

    #[inline]
    fn layer1(&self, i: usize) -> usize {
        self.0.layer1(i) & self.1.layer1(i)
    }

    #[inline]
    fn layer0(&self, i: usize) -> usize {
        self.0.layer0(i) & self.1.layer0(i)
    }

    #[inline]
    fn contains(&self, i: Index) -> bool {
        self.0.contains(i) && self.1.contains(i)
    }
}

impl<A: DrainableBitSet, B: DrainableBitSet> DrainableBitSet
    for BitSetAnd<A, B>
{
    #[inline]
    fn remove(&mut self, i: Index) -> bool {
        if self.contains(i) {
            self.0.remove(i);
            self.1.remove(i);
            true
        } else {
            false
        }
    }
}

/// `BitSetOr` takes two [`BitSetLike`] items, and merges the masks
/// returning a new virtual set, which represents an merged of the
/// two original sets.
///
/// [`BitSetLike`]: ../trait.BitSetLike.html
#[derive(Debug)]
pub struct BitSetOr<A: BitSetLike, B: BitSetLike>(pub A, pub B);

impl<A: BitSetLike, B: BitSetLike> BitSetLike for BitSetOr<A, B> {
    #[inline]
    fn layer3(&self) -> usize {
        self.0.layer3() | self.1.layer3()
    }

    #[inline]
    fn layer2(&self, i: usize) -> usize {
        self.0.layer2(i) | self.1.layer2(i)
    }

    #[inline]
    fn layer1(&self, i: usize) -> usize {
        self.0.layer1(i) | self.1.layer1(i)
    }

    #[inline]
    fn layer0(&self, i: usize) -> usize {
        self.0.layer0(i) | self.1.layer0(i)
    }

    #[inline]
    fn contains(&self, i: Index) -> bool {
        self.0.contains(i) || self.1.contains(i)
    }
}

impl<A: DrainableBitSet, B: DrainableBitSet> DrainableBitSet
    for BitSetOr<A, B>
{
    #[inline]
    fn remove(&mut self, i: Index) -> bool {
        if self.contains(i) {
            self.0.remove(i);
            self.1.remove(i);
            true
        } else {
            false
        }
    }
}

/// `BitSetNot` takes a [`BitSetLike`] item, and produced an inverted virtual
/// set. Note: the implementation is sub-optimal because layers 1-3 are not
/// active.
///
/// [`BitSetLike`]: ../trait.BitSetLike.html
#[derive(Debug)]
pub struct BitSetNot<A: BitSetLike>(pub A);

impl<A: BitSetLike> BitSetLike for BitSetNot<A> {
    #[inline]
    fn layer3(&self) -> usize {
        !0
    }

    #[inline]
    fn layer2(&self, _: usize) -> usize {
        !0
    }

    #[inline]
    fn layer1(&self, _: usize) -> usize {
        !0
    }

    #[inline]
    fn layer0(&self, i: usize) -> usize {
        !self.0.layer0(i)
    }

    #[inline]
    fn contains(&self, i: Index) -> bool {
        !self.0.contains(i)
    }
}

/// `BitSetXor` takes two [`BitSetLike`] items, and merges the masks
/// returning a new virtual set, which represents an merged of the
/// two original sets.
///
/// [`BitSetLike`]: ../trait.BitSetLike.html
#[derive(Debug)]
pub struct BitSetXor<A: BitSetLike, B: BitSetLike>(pub A, pub B);

impl<A: BitSetLike, B: BitSetLike> BitSetLike for BitSetXor<A, B> {
    #[inline]
    fn layer3(&self) -> usize {
        let xor = BitSetAnd(
            BitSetOr(&self.0, &self.1),
            BitSetNot(BitSetAnd(&self.0, &self.1)),
        );
        xor.layer3()
    }

    #[inline]
    fn layer2(&self, id: usize) -> usize {
        let xor = BitSetAnd(
            BitSetOr(&self.0, &self.1),
            BitSetNot(BitSetAnd(&self.0, &self.1)),
        );
        xor.layer2(id)
    }

    #[inline]
    fn layer1(&self, id: usize) -> usize {
        let xor = BitSetAnd(
            BitSetOr(&self.0, &self.1),
            BitSetNot(BitSetAnd(&self.0, &self.1)),
        );
        xor.layer1(id)
    }

    #[inline]
    fn layer0(&self, id: usize) -> usize {
        let xor = BitSetAnd(
            BitSetOr(&self.0, &self.1),
            BitSetNot(BitSetAnd(&self.0, &self.1)),
        );
        xor.layer0(id)
    }

    #[inline]
    fn contains(&self, i: Index) -> bool {
        BitSetAnd(
            BitSetOr(&self.0, &self.1),
            BitSetNot(BitSetAnd(&self.0, &self.1)),
        )
        .contains(i)
    }
}

/// `BitSetAll` is a bitset with all bits set. Essentially the same as
/// `BitSetNot(BitSet::new())` but without any allocation.
#[derive(Debug)]
pub struct BitSetAll;
impl BitSetLike for BitSetAll {
    #[inline]
    fn layer3(&self) -> usize {
        usize::MAX
    }

    #[inline]
    fn layer2(&self, _id: usize) -> usize {
        usize::MAX
    }

    #[inline]
    fn layer1(&self, _id: usize) -> usize {
        usize::MAX
    }

    #[inline]
    fn layer0(&self, _id: usize) -> usize {
        usize::MAX
    }

    #[inline]
    fn contains(&self, _i: Index) -> bool {
        true
    }
}

macro_rules! operator {
    ( impl < ( $( $lifetime:tt )* ) ( $( $arg:ident ),* ) > for $bitset:ty ) => {
        impl<$( $lifetime, )* $( $arg ),*> IntoIterator for $bitset
            where $( $arg: BitSetLike ),*
        {
            type Item = <BitIter<Self> as Iterator>::Item;
            type IntoIter = BitIter<Self>;
            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }

        impl<$( $lifetime, )* $( $arg ),*> Not for $bitset
            where $( $arg: BitSetLike ),*
        {
            type Output = BitSetNot<Self>;
            fn not(self) -> Self::Output {
                BitSetNot(self)
            }
        }

        impl<$( $lifetime, )* $( $arg, )* T> BitAnd<T> for $bitset
            where T: BitSetLike,
                  $( $arg: BitSetLike ),*
        {
            type Output = BitSetAnd<Self, T>;
            fn bitand(self, rhs: T) -> Self::Output {
                BitSetAnd(self, rhs)
            }
        }

        impl<$( $lifetime, )* $( $arg, )* T> BitOr<T> for $bitset
            where T: BitSetLike,
                  $( $arg: BitSetLike ),*
        {
            type Output = BitSetOr<Self, T>;
            fn bitor(self, rhs: T) -> Self::Output {
                BitSetOr(self, rhs)
            }
        }

        impl<$( $lifetime, )* $( $arg, )* T> BitXor<T> for $bitset
            where T: BitSetLike,
                  $( $arg: BitSetLike ),*
        {
            type Output = BitSetXor<Self, T>;
            fn bitxor(self, rhs: T) -> Self::Output {
                BitSetXor(self, rhs)
            }
        }

    }
}

operator!(impl<()()> for BitSet);
operator!(impl<('a)()> for &'a BitSet);
operator!(impl<()()> for AtomicBitSet);
operator!(impl<('a)()> for &'a AtomicBitSet);
operator!(impl<()(A)> for BitSetNot<A>);
operator!(impl<('a)(A)> for &'a BitSetNot<A>);
operator!(impl<()(A, B)> for BitSetAnd<A, B>);
operator!(impl<('a)(A, B)> for &'a BitSetAnd<A, B>);
operator!(impl<()(A, B)> for BitSetOr<A, B>);
operator!(impl<('a)(A, B)> for &'a BitSetOr<A, B>);
operator!(impl<()(A, B)> for BitSetXor<A, B>);
operator!(impl<('a)(A, B)> for &'a BitSetXor<A, B>);
operator!(impl<()()> for BitSetAll);
operator!(impl<('a)()> for &'a BitSetAll);

macro_rules! iterator {
    ($bitset:ident) => {
        impl FromIterator<Index> for $bitset {
            fn from_iter<T>(iter: T) -> Self
            where
                T: IntoIterator<Item = Index>,
            {
                let mut bitset = $bitset::new();
                for item in iter {
                    bitset.add(item);
                }
                bitset
            }
        }

        impl<'a> FromIterator<&'a Index> for $bitset {
            fn from_iter<T>(iter: T) -> Self
            where
                T: IntoIterator<Item = &'a Index>,
            {
                let mut bitset = $bitset::new();
                for item in iter {
                    bitset.add(*item);
                }
                bitset
            }
        }

        impl Extend<Index> for $bitset {
            fn extend<T>(&mut self, iter: T)
            where
                T: IntoIterator<Item = Index>,
            {
                for item in iter {
                    self.add(item);
                }
            }
        }

        impl<'a> Extend<&'a Index> for $bitset {
            fn extend<T>(&mut self, iter: T)
            where
                T: IntoIterator<Item = &'a Index>,
            {
                for item in iter {
                    self.add(*item);
                }
            }
        }
    };
}

iterator!(BitSet);
iterator!(AtomicBitSet);

#[cfg(test)]
mod tests {
    use BitSet;
    use BitSetLike;
    use BitSetXor;
    use Index;

    #[test]
    fn operators() {
        let mut bitset = BitSet::new();
        bitset.add(1);
        bitset.add(3);
        bitset.add(5);
        bitset.add(15);
        bitset.add(200);
        bitset.add(50001);

        let mut other = BitSet::new();
        other.add(1);
        other.add(3);
        other.add(50000);
        other.add(50001);

        {
            let not = &bitset & !&bitset;
            assert_eq!(not.iter().count(), 0);
        }

        {
            let either = &bitset | &other;
            let collected = either.iter().collect::<Vec<Index>>();
            assert_eq!(collected, vec![1, 3, 5, 15, 200, 50000, 50001]);

            let either_sanity = bitset.clone() | other.clone();
            assert_eq!(collected, either_sanity.iter().collect::<Vec<Index>>());
        }

        {
            let same = &bitset & &other;
            let collected = same.iter().collect::<Vec<Index>>();
            assert_eq!(collected, vec![1, 3, 50001]);

            let same_sanity = bitset.clone() & other.clone();
            assert_eq!(collected, same_sanity.iter().collect::<Vec<Index>>());
        }

        {
            let exclusive = &bitset ^ &other;
            let collected = exclusive.iter().collect::<Vec<Index>>();
            assert_eq!(collected, vec![5, 15, 200, 50000]);

            let exclusive_sanity = bitset.clone() ^ other.clone();
            assert_eq!(
                collected,
                exclusive_sanity.iter().collect::<Vec<Index>>()
            );
        }
    }

    #[test]
    fn xor() {
        // 0011
        let mut bitset = BitSet::new();
        bitset.add(2);
        bitset.add(3);
        bitset.add(50000);

        // 0101
        let mut other = BitSet::new();
        other.add(1);
        other.add(3);
        other.add(50000);
        other.add(50001);

        {
            // 0110
            let xor = BitSetXor(&bitset, &other);
            let collected = xor.iter().collect::<Vec<Index>>();
            assert_eq!(collected, vec![1, 2, 50001]);
        }
    }
}
