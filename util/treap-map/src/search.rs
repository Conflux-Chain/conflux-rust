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

pub enum SearchResult<'a, C: TreapMapConfig> {
    Abort,
    LeftMost,
    Found {
        base_weight: C::Weight,
        node: &'a Node<C>,
    },
    RightMost(C::Weight),
}

impl<'a, C: TreapMapConfig> SearchResult<'a, C> {
    pub fn maybe_value(&self) -> Option<&'a C::Value> {
        if let SearchResult::Found { node, .. } = self {
            Some(&node.value)
        } else {
            None
        }
    }

    pub fn or(self, other: Self) -> Self {
        if matches!(self, SearchResult::Found { .. }) {
            self
        } else {
            other
        }
    }

    pub fn check_dir(self, left: bool) -> Self {
        if matches!(self, SearchResult::LeftMost) && !left {
            return SearchResult::Abort;
        }
        if matches!(self, SearchResult::RightMost(_)) && left {
            return SearchResult::Abort;
        }
        self
    }
}

#[inline]
pub fn prefix_sum_search<C, F>(
    node: &Node<C>, base_weight: C::Weight, mut f: F,
) -> SearchResult<C>
where
    C: TreapMapConfig,
    F: FnMut(&C::Weight, &Node<C>) -> SearchDirection<C::Weight>,
{
    use SearchDirection::*;

    let left_weight = if let Some(ref left) = node.left {
        C::Weight::consolidate(&base_weight, &left.sum_weight)
    } else {
        base_weight.clone()
    };
    let search_dir = f(&left_weight, &node);

    let found = SearchResult::Found {
        base_weight: left_weight,
        node: &node,
    };

    match (search_dir, &node.left, &node.right) {
        (Abort, _, _) => SearchResult::Abort,
        (Stop, _, _) | (LeftOrStop, None, _) | (RightOrStop(_), _, None) => {
            found
        }
        (Left, None, _) => SearchResult::LeftMost,
        (Right(weight), _, None) => SearchResult::RightMost(weight),
        (Left, Some(left), _) => {
            prefix_sum_search(left, base_weight, f).check_dir(true)
        }
        (LeftOrStop, Some(left), _) => prefix_sum_search(left, base_weight, f)
            .or(found)
            .check_dir(true),
        (Right(weight), _, Some(right)) => {
            prefix_sum_search(right, weight, f).check_dir(false)
        }
        (RightOrStop(weight), _, Some(right)) => {
            prefix_sum_search(right, weight, f)
                .or(found)
                .check_dir(false)
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
                .search(|_, node| match i.cmp(&node.value) {
                    Less => Left,
                    Equal => Stop,
                    // If the search doesn't read weight, the carried weight
                    // could by anything. Some implementation relies on this
                    // feature
                    Greater => Right(0),
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
}

mod impl_std_trait {
    use super::{Node, SearchResult, TreapMapConfig};
    use core::{
        cmp::PartialEq,
        fmt::{self, Debug, Formatter},
    };

    impl<'a, C: TreapMapConfig> Debug for SearchResult<'a, C>
    where
        C::Weight: Debug,
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

    impl<'a, C: TreapMapConfig> PartialEq for SearchResult<'a, C>
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
