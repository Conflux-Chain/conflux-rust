use std::fmt::Debug;

use super::{
    config::{ConsoliableWeight, TreapMapConfig},
    node::Node,
};

/// Represents the directions for the search in [`accumulate_weight_search`].
///
/// This enum is used by the user-provided function to indicate how the search
/// should proceed or terminate in `accumulate_weight_search`.
#[derive(Debug, PartialEq, Eq)]
pub enum SearchDirection<W> {
    /// Indicates to abort the search immediately.
    /// This stops further searching in any subtree.
    Abort,

    /// Indicates to continue the search in the left subtree.
    /// This is used when the current search result is unacceptable and the
    /// search should move left.
    Left,

    /// Indicates that the current search result is acceptable and the search
    /// should stop.
    Stop,

    /// Indicates to continue the search in the right subtree, with the
    /// provided weight `W`. This is used when the current search result is
    /// unacceptable and the search should move right. The user function is
    /// expected to merge the accumulate weight with the node weight and
    /// provide it in this variant to avoid recalculating it in
    /// [`accumulate_weight_search`].
    Right(W),

    /// Indicates that the current search result is acceptable, but the search
    /// should still continue in the left subtree. If the subtree yields no
    /// results, the current result is returned.
    LeftOrStop,

    /// Similar to `LeftOrStop`, but for the right subtree.
    /// Indicates that the current search result is acceptable, but the search
    /// should still continue in the right subtree. If the subtree yields
    /// no results, the current result is returned, along with the merged
    /// weight. The user function is expected to merge the accumulate
    /// weight with the node weight and provide it in this variant to avoid
    /// recalculating it in [`accumulate_weight_search`].
    RightOrStop(W),
}

impl<W> SearchDirection<W> {
    #[inline]
    pub(crate) fn map_into<T, F>(self, f: F) -> SearchDirection<T>
    where F: FnOnce(W) -> T {
        match self {
            SearchDirection::Abort => SearchDirection::Abort,
            SearchDirection::Left => SearchDirection::Left,
            SearchDirection::Stop => SearchDirection::Stop,
            SearchDirection::Right(v) => SearchDirection::Right(f(v)),
            SearchDirection::LeftOrStop => SearchDirection::LeftOrStop,
            SearchDirection::RightOrStop(v) => {
                SearchDirection::RightOrStop(f(v))
            }
        }
    }
}

/// Represents the possible outcomes of the `accumulate_weight_search`.
///
/// This enum encapsulates the results that can be returned by
/// `accumulate_weight_search`, indicating the outcome of the search within a
/// treap map.
pub enum SearchResult<'a, C: TreapMapConfig, W: ConsoliableWeight> {
    /// Indicates that the search was aborted.
    /// This variant is used when no feasible result is found and the search
    /// position is neither at the extreme left nor the extreme right of
    /// the treap.
    Abort,

    /// Indicates that the search reached the leftmost edge of the entire treap
    /// without finding a feasible result.
    LeftMost,

    /// Represents a successful search, indicating a feasible result has been
    /// found. Contains `base_weight`, which is the total weight from the
    /// leftmost edge up to but not including the current node,
    /// and a reference to the `node` itself.
    Found { base_weight: W, node: &'a Node<C> },

    /// Indicates that the search reached the rightmost edge of the entire
    /// treap without finding a feasible result. Also returns the total
    /// weight of the entire tree (`RightMost(W)`).
    RightMost(W),
}

impl<'a, C: TreapMapConfig, W: ConsoliableWeight> SearchResult<'a, C, W> {
    pub fn maybe_value(&self) -> Option<&'a C::Value> {
        if let SearchResult::Found { node, .. } = self {
            Some(&node.value)
        } else {
            None
        }
    }
}

/// Performs a binary search in a treap-map.
///
/// This function conducts a binary search within a treap-map structure, where
/// at each step it can access the accumulated weight from the leftmost node to
/// the current node.
///
/// # Parameters
/// - `node`: The root node of the treap-map.
/// - `f`: A search function that takes the accumulated weight from the leftmost
///   node to the current node (excluding the current node) and the current node
///   itself. It returns a search direction (see [`SearchDirection`
///   struct][SearchDirection] for more details).
/// - `extract`: A function to extract a subset of the weight stored in the
///   treap-map. This allows for avoiding the reading and maintenance of fields
///   that are not needed during the search.
#[inline]
pub fn accumulate_weight_search<C, W, F, E>(
    root: &Node<C>, mut f: F, extract: E,
) -> SearchResult<C, W>
where
    C: TreapMapConfig,
    F: FnMut(&W, &Node<C>) -> SearchDirection<W>,
    W: ConsoliableWeight,
    E: Fn(&C::Weight) -> &W,
{
    use SearchDirection::*;

    let mut node = root;
    let mut base_weight = W::empty();

    let mut candidate_result = None;

    let mut all_left = true;
    let mut all_right = true;

    // Using loops instead of recursion can improve performance by 20%.
    loop {
        let left_weight = if let Some(ref left) = node.left {
            W::consolidate(&base_weight, extract(&left.sum_weight))
        } else {
            base_weight.clone()
        };
        let search_dir = f(&left_weight, &node);

        let found = SearchResult::Found {
            base_weight: left_weight,
            node: &node,
        };

        if matches!(search_dir, Left | LeftOrStop) {
            all_right = false;
        }

        if matches!(search_dir, Right(_) | RightOrStop(_)) {
            all_left = false;
        }

        let next_node = match search_dir {
            Right(_) | RightOrStop(_) => &node.right,
            Left | LeftOrStop => &node.left,
            Abort => {
                return candidate_result.unwrap_or(SearchResult::Abort);
            }
            Stop => {
                return found;
            }
        };

        if matches!(search_dir, Stop | LeftOrStop | RightOrStop(_)) {
            candidate_result = Some(found);
        }

        let right_weight = match search_dir {
            Right(w) | RightOrStop(w) => Some(w),
            _ => None,
        };

        if let Some(found_node) = next_node {
            node = found_node;
            if let Some(w) = right_weight {
                base_weight = w;
            }
        } else {
            if let Some(result) = candidate_result {
                return result;
            } else if all_left {
                return SearchResult::LeftMost;
            } else if all_right {
                return SearchResult::RightMost(right_weight.unwrap());
            } else {
                return SearchResult::Abort;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SearchDirection::*,
        SearchResult::{self, *},
    };
    use crate::{ConsoliableWeight, SharedKeyTreapMapConfig, TreapMap};
    use std::cmp::Ordering::*;

    #[derive(Debug, PartialEq, Eq)]
    struct SearchTestConfig;
    impl SharedKeyTreapMapConfig for SearchTestConfig {
        type Key = usize;
        type Value = usize;
        type Weight = usize;
    }

    fn default_map(n: usize) -> TreapMap<SearchTestConfig> {
        let mut map = TreapMap::<SearchTestConfig>::new();
        for i in 1..=n {
            map.insert(i * 3, i * 3, 3);
        }
        map
    }

    #[test]
    fn search_no_weight() {
        let map = default_map(1000);
        for i in 0usize..=3003 {
            let res = map
                .search_no_weight(|node| match i.cmp(&node.value) {
                    Less => Left,
                    Equal => Stop,
                    Greater => Right(()),
                })
                .unwrap();
            if i < 3 {
                assert_eq!(res, LeftMost)
            } else if i > 3000 {
                assert!(matches!(res, RightMost(_)));
            } else if i % 3 != 0 {
                assert_eq!(res, SearchResult::Abort);
            } else {
                assert_eq!(*res.maybe_value().unwrap(), i);
            }
        }
    }

    #[test]
    fn search_with_weight() {
        let map = default_map(1000);
        for i in 0usize..=3003 {
            let res = map
                .search(|left_weight, node| match i.cmp(&node.value) {
                    Less => Left,
                    Equal => Stop,
                    Greater => Right(ConsoliableWeight::consolidate(
                        left_weight,
                        &node.weight,
                    )),
                })
                .unwrap();
            if i < 3 {
                assert_eq!(res, LeftMost)
            } else if i > 3000 {
                assert!(matches!(res, RightMost(_)));
            } else if i % 3 != 0 {
                assert_eq!(res, SearchResult::Abort);
            } else {
                if let Found { base_weight, node } = res {
                    assert_eq!(base_weight, i - 3);
                    assert_eq!(node.key, i);
                } else {
                    unreachable!("Unexpected");
                }
            }
        }
    }

    #[test]
    fn search_last_vaild() {
        let map = default_map(1000);
        for i in 0usize..=3003 {
            let res = map
                .search(|left_weight, node| {
                    if node.value <= i {
                        RightOrStop(ConsoliableWeight::consolidate(
                            left_weight,
                            &node.weight,
                        ))
                    } else {
                        Left
                    }
                })
                .unwrap();
            if i < 3 {
                assert_eq!(res, LeftMost);
            } else {
                let mut x = i;
                if x >= 3000 {
                    x = 3000;
                }
                if let Found { base_weight, node } = res {
                    assert_eq!(node.key, x - x % 3);
                    assert_eq!(base_weight, node.key - 3);
                } else {
                    unreachable!("Unexpected");
                }
            }
        }
    }

    #[test]
    fn search_first_valid() {
        let map = default_map(1000);
        for i in 0usize..=3003 {
            let res = map
                .search(|left_weight, node| {
                    if node.value <= i {
                        Right(ConsoliableWeight::consolidate(
                            left_weight,
                            &node.weight,
                        ))
                    } else {
                        LeftOrStop
                    }
                })
                .unwrap();
            if i >= 3000 {
                assert_eq!(res, RightMost(3000));
            } else {
                if let Found { base_weight, node } = res {
                    assert_eq!(node.key, i - i % 3 + 3);
                    assert_eq!(base_weight, node.key - 3);
                } else {
                    unreachable!("Unexpected");
                }
            }
        }
    }

    #[test]
    fn search_left_most() {
        let map = default_map(1000);
        let res = map.search_no_weight(|_| LeftOrStop).unwrap();

        if let Found { node, .. } = res {
            assert_eq!(node.key, 3);
        } else {
            unreachable!("Unexpected");
        }
    }

    #[test]
    fn iter_range() {
        for n in 1..=1000 {
            let map: TreapMap<SearchTestConfig> = default_map(n);
            for i in 0..=(3 * (n + 1)) {
                let x: Vec<usize> = map.iter_range(&i).map(|x| x.key).collect();
                let y: Vec<usize> =
                    (3usize..=(3 * n)).step_by(3).filter(|x| *x >= i).collect();
                assert_eq!(x, y);
            }
        }
    }
}

mod impl_std_trait {
    use crate::ConsoliableWeight;

    use super::{Node, SearchResult, TreapMapConfig};
    use core::{
        cmp::PartialEq,
        fmt::{self, Debug, Formatter},
    };

    impl<'a, C: TreapMapConfig, W: ConsoliableWeight> Debug
        for SearchResult<'a, C, W>
    where
        W: Debug,
        Node<C>: Debug,
    {
        #[inline]
        fn fmt(&self, f: &mut Formatter) -> fmt::Result {
            match self {
                SearchResult::Abort => Formatter::write_str(f, "Abort"),
                SearchResult::LeftMost => Formatter::write_str(f, "LeftMost"),
                SearchResult::Found { base_weight, node } => f
                    .debug_struct("Found")
                    .field("base_weight", base_weight)
                    .field("node", node)
                    .finish(),
                SearchResult::RightMost(w) => {
                    f.debug_tuple("RightMost").field(w).finish()
                }
            }
        }
    }

    impl<'a, C: TreapMapConfig, W: ConsoliableWeight> PartialEq
        for SearchResult<'a, C, W>
    where
        C::Weight: PartialEq,
        Node<C>: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (
                    Self::Found {
                        base_weight: l_base_weight,
                        node: l_node,
                    },
                    Self::Found {
                        base_weight: r_base_weight,
                        node: r_node,
                    },
                ) => l_base_weight == r_base_weight && l_node == r_node,
                (Self::RightMost(l0), Self::RightMost(r0)) => l0 == r0,
                _ => {
                    core::mem::discriminant(self)
                        == core::mem::discriminant(other)
                }
            }
        }
    }
}
