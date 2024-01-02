use std::fmt::Debug;

use super::{
    config::{TreapMapConfig, WeightConsolidate},
    node::Node,
};
#[derive(Debug, PartialEq, Eq)]
pub enum SearchDirection<W> {
    Abort,
    Left,
    Stop,
    Right(W),
    LeftOrStop,
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

pub enum SearchResult<'a, C: TreapMapConfig, W: WeightConsolidate> {
    Abort,
    LeftMost,
    Found { base_weight: W, node: &'a Node<C> },
    RightMost(W),
}

impl<'a, C: TreapMapConfig, W: WeightConsolidate> SearchResult<'a, C, W> {
    pub fn maybe_value(&self) -> Option<&'a C::Value> {
        if let SearchResult::Found { node, .. } = self {
            Some(&node.value)
        } else {
            None
        }
    }
}

#[inline]
pub fn prefix_sum_search<C, W, F, E>(
    node: &Node<C>, base_weight: W, mut f: F, extract: E,
) -> SearchResult<C, W>
where
    C: TreapMapConfig,
    F: FnMut(&W, &Node<C>) -> SearchDirection<W>,
    W: WeightConsolidate,
    E: Fn(&C::Weight) -> &W,
{
    use SearchDirection::*;

    let mut node = node;
    let mut base_weight = base_weight;

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

        if matches!(search_dir, Right(_)|RightOrStop(_)) {
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
    use crate::{SharedKeyTreapMapConfig, TreapMap, WeightConsolidate};
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
                    // If the search doesn't read weight, the carried weight
                    // could by anything. Some implementation relies on this
                    // feature
                    Greater => Right(WeightConsolidate::consolidate(
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
                        RightOrStop(WeightConsolidate::consolidate(
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
                        Right(WeightConsolidate::consolidate(
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
    use crate::WeightConsolidate;

    use super::{Node, SearchResult, TreapMapConfig};
    use core::{
        cmp::PartialEq,
        fmt::{self, Debug, Formatter},
    };

    impl<'a, C: TreapMapConfig, W: WeightConsolidate> Debug
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

    impl<'a, C: TreapMapConfig, W: WeightConsolidate> PartialEq
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
