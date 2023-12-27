use super::{
    config::{TreapMapConfig, WeightConsolidate},
    node::Node,
};
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
        node_weight: &'a C::Weight,
        value: &'a C::Value,
    },
    RightMost(C::Weight),
}

impl<'a, C: TreapMapConfig> SearchResult<'a, C> {
    pub fn maybe_value(&self) -> Option<&'a C::Value> {
        if let SearchResult::Found { value, .. } = self {
            Some(value)
        } else {
            None
        }
    }
}

pub fn prefix_sum_search<C, F>(
    node: &Node<C>, base_weight: C::Weight, mut f: F,
) -> SearchResult<C>
where
    C: TreapMapConfig,
    F: FnMut(&C::Weight, &C::Weight) -> SearchDirection<C::Weight>,
{
    use SearchDirection::*;

    let left_weight = if let Some(ref left) = node.left {
        C::Weight::consolidate(&base_weight, &left.sum_weight)
    } else {
        base_weight.clone()
    };
    let search_dir = f(&left_weight, &node.weight);

    match (search_dir, &node.left, &node.right) {
        (Stop, _, _) | (LeftOrStop, None, _) | (RightOrStop(_), _, None) => {
            SearchResult::Found {
                base_weight,
                node_weight: &node.weight,
                value: &node.value,
            }
        }
        (Left, None, _) => SearchResult::LeftMost,
        (Right(weight), _, None) => SearchResult::RightMost(weight),
        // FIXME: an elegant style is `(Left | LeftOrStop, Some(left), _)`, but
        // it can not pass Conflux code formatter, which is in a very early
        // version.
        (Left, Some(left), _) | (LeftOrStop, Some(left), _) => {
            prefix_sum_search(left, base_weight, f)
        }
        (Right(weight), _, Some(right))
        | (RightOrStop(weight), _, Some(right)) => {
            prefix_sum_search(right, weight, f)
        }
    }
}
