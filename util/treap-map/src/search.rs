use super::{
    config::{TreapMapConfig, WeightConsolidate},
    node::Node,
};
#[derive(Debug)]
pub enum SearchDirection<W> {
    Left,
    Stop,
    Right(W),
    LeftOrStop,
    RightOrStop(W),
}

pub enum SearchResult<'a, C: TreapMapConfig> {
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
        (Stop, _, _) | (LeftOrStop, None, _) | (RightOrStop(_), _, None) => {
            found
        }
        (Left, None, _) => SearchResult::LeftMost,
        (Right(weight), _, None) => SearchResult::RightMost(weight),
        (Left, Some(left), _) => prefix_sum_search(left, base_weight, f),
        (LeftOrStop, Some(left), _) => {
            prefix_sum_search(left, base_weight, f).or(found)
        }
        (Right(weight), _, Some(right)) => prefix_sum_search(right, weight, f),
        (RightOrStop(weight), _, Some(right)) => {
            prefix_sum_search(right, weight, f).or(found)
        }
    }
}
