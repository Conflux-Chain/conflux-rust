use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use primitives::Zero;
use std::{cmp::Ordering, ops::Add};

use crate::Direction;

/// The weight type in a Treap. It is used to perform operations like
/// calculating sums or maximum values of an interval in logrithmic time over
/// treap.
pub trait WeightConsolidate: Clone + Eq {
    /// Create a default or 'zero' value for the weight. Consolidating with this
    /// value should not change the other value.
    fn empty() -> Self;

    /// Combine two weights into a single one.
    fn consolidate(a: &Self, b: &Self) -> Self;

    /// Combine another weight into `self`. It allows for implementing more
    /// efficient in-place consolidation.
    fn accure(&mut self, other: &Self) {
        *self = Self::consolidate(&*self, other);
    }
}

impl<T: Add<Output = T> + Clone + Zero + Eq> WeightConsolidate for T {
    fn empty() -> Self { T::zero() }

    fn consolidate(a: &Self, b: &Self) -> Self { a.clone() + b.clone() }

    fn accure(&mut self, other: &Self) { *self = self.clone() + other.clone() }
}

/// `TreapMap` is a struct which implements a treap which can be indexed by a
/// different key (type `SearchKey`). The associate type `SortKey` and
/// `SearchKey` defines how to order node in treap collaborately.
///
/// As the user only needs to provider the `SearchKey` in searching an element,
/// but the underlying treap is ordered by both `SortKey` and `SearchKey`.
/// `TreapMap` also maintains `KeyMng` to recover `SortKey` from `SearchKey`. It
/// could be a `HashMap`.
///
/// If `TreapMap` is indexed in the same key as the inside treap. The `SortKey`
/// can be deprecated to `()` and the `KeyMng` can be deprecated to a unit type.
/// Since it is compiled through static dispatch, unnecessary operations will be
/// optimized away.
pub trait TreapMapConfig: Sized {
    /// The search key type in the TreapMap, supporting query/remove a node by
    /// key.
    type SearchKey;
    /// The sort key in the treap.
    type SortKey;
    /// The stored value.
    type Value: Clone;
    /// The external map which can computing `SortKey` from `SearchKey`. If not
    /// needed, it could be a unit type.
    type ExtMap: KeyMngTrait<Self>;
    /// The consolidable weight.
    type Weight: WeightConsolidate;

    /// Compare the key.
    fn next_node_dir(
        me: (&Self::SortKey, &Self::SearchKey),
        other: (&Self::SortKey, &Self::SearchKey),
    ) -> Option<Direction>;
}

/// Searching in `Treap` requires sort key. This trait manages the relationship
/// among sort keys, search keys and values in a Treap. This is necessary when
/// the sort key is not directly derivable from the search key or is not a null
/// element.
pub trait KeyMngTrait<C: TreapMapConfig>: Default {
    /// Invoked when a new key-value pair is changed in the Treap.
    fn view_update(
        &mut self, key: &C::SearchKey, value: Option<&C::Value>,
        old_value: Option<&C::Value>,
    );
    /// Number of the keys
    fn len(&self) -> usize;
    /// Retrieve the sort key for a given search key.
    /// Returns `None` if the search key is not in the treap.
    fn get_sort_key(&self, key: &C::SearchKey) -> Option<C::SortKey>;
    /// Generate the sort key from a key-value pair.
    fn make_sort_key(&self, key: &C::SearchKey, value: &C::Value)
        -> C::SortKey;
}

/// If `TreapMap` is indexed in the same key as the inside treap, it can be
/// configed in a simple way.
pub trait SharedKeyTreapMapConfig {
    /// The search key in the TreapMap.
    type Key: Ord;
    /// The stored value.
    type Value: Clone;
    /// The consolidable weight.
    type Weight: WeightConsolidate;
}

impl<T: SharedKeyTreapMapConfig> TreapMapConfig for T {
    type ExtMap = Counter;
    type SearchKey = T::Key;
    type SortKey = ();
    type Value = T::Value;
    type Weight = T::Weight;

    #[inline]
    fn next_node_dir(
        (_, me): (&(), &Self::SearchKey), (_, other): (&(), &Self::SearchKey),
    ) -> Option<Direction> {
        match me.cmp(other) {
            Ordering::Less => Some(Direction::Left),
            Ordering::Equal => None,
            Ordering::Greater => Some(Direction::Right),
        }
    }
}
#[derive(Default)]
pub struct Counter(pub usize);

impl<C: TreapMapConfig<SortKey = ()>> KeyMngTrait<C> for Counter {
    #[inline]
    fn view_update(
        &mut self, _key: &C::SearchKey, value: Option<&C::Value>,
        old_value: Option<&C::Value>,
    )
    {
        if value.is_some() {
            self.0 += 1;
        }
        if old_value.is_some() {
            self.0 -= 1
        }
    }

    fn len(&self) -> usize { self.0 }

    fn get_sort_key(&self, _key: &C::SearchKey) -> Option<()> { Some(()) }

    fn make_sort_key(
        &self, _key: &C::SearchKey, _value: &C::Value,
    ) -> C::SortKey {
        ()
    }
}

impl MallocSizeOf for Counter {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops)
    }
}
