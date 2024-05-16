// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    config::{ConsoliableWeight, Direction, TreapMapConfig},
    update::{OpResult, TreapNodeUpdate},
};

use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use std::mem;

/// A node in a treap-map data structure.
///
/// The `Node` struct represents a node in a treap-map and contains various
/// key-value pairs and metadata required for the proper functioning and
/// maintenance of the treap-map. Direct modification of these fields is not
/// recommended outside of the `TreapMap::update` function, as this function
/// correctly maintains the integrity of the treap-map.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Node<C: TreapMapConfig> {
    /// The key exposed externally. Used for key-based searches within the
    /// treap-map.
    pub key: C::SearchKey,

    /// The value stored in the node.
    pub value: C::Value,

    /// The sorting key for the treap-map. If the type is `()`, the
    /// `search_key` is used for sorting.
    pub sort_key: C::SortKey,

    /// The weight of the node, used by the treap-map to maintain accumulated
    /// weights.
    pub weight: C::Weight,

    /// The sum of the weights of this node and its descendants. Maintained
    /// internally for efficient operations.
    pub(crate) sum_weight: C::Weight,

    /// A priority value used by the treap algorithm, typically a random
    /// number.
    priority: u64,

    /// The left child of the node in the treap-map structure.
    pub(crate) left: Option<Box<Node<C>>>,

    /// The right child of the node in the treap-map structure.
    pub(crate) right: Option<Box<Node<C>>>,
}

impl<C: TreapMapConfig> Node<C> {
    pub fn new(
        key: C::SearchKey, value: C::Value, sort_key: C::SortKey,
        weight: C::Weight, priority: u64,
    ) -> Node<C> {
        Node {
            key,
            value,
            sort_key,
            sum_weight: weight.clone(),
            weight,
            priority,
            left: None,
            right: None,
        }
    }

    pub(crate) fn get(
        &self, sort_key: &C::SortKey, key: &C::SearchKey,
    ) -> Option<&C::Value> {
        match C::next_node_dir((sort_key, key), (&self.sort_key, &self.key)) {
            None => Some(&self.value),
            Some(Direction::Left) => self.left.as_ref()?.get(sort_key, key),
            Some(Direction::Right) => self.right.as_ref()?.get(sort_key, key),
        }
    }

    pub(crate) fn update_inner<U: TreapNodeUpdate<C>>(
        maybe_node: &mut Option<Box<Node<C>>>, updater: U,
    ) -> (U::Ret, bool, bool) {
        // Compare the key
        let next_node_dir = if let Some(node) = maybe_node {
            C::next_node_dir(updater.treap_key(), (&node.sort_key, &node.key))
        } else {
            None
        };

        // Goto the next node or apply on the current node (if hit)
        let (ret, update_weight, mut update_priority) = match next_node_dir {
            None => {
                let update_result = updater.update_node(maybe_node.as_mut());
                Node::process_update_result::<U>(maybe_node, update_result)
            }

            Some(dir) => {
                let node = maybe_node.as_mut().unwrap();
                let next_node = match dir {
                    Direction::Left => &mut node.left,
                    Direction::Right => &mut node.right,
                };
                Node::update_inner(next_node, updater)
            }
        };

        // Update the sum_weight and priority inneeded.
        if let Some(node) = maybe_node.as_mut() {
            if update_weight {
                node.update_weight()
            }
            if let (Some(dir), true) = (next_node_dir, update_priority) {
                match dir {
                    Direction::Left
                        if node.left.as_ref().map_or(false, |left| {
                            node.priority < left.priority
                        }) =>
                    {
                        node.right_rotate();
                    }
                    Direction::Right
                        if node.right.as_ref().map_or(false, |right| {
                            node.priority < right.priority
                        }) =>
                    {
                        node.left_rotate();
                    }
                    _ => {
                        update_priority = false;
                    }
                }
            }
        }
        (ret, update_weight, update_priority)
    }

    fn process_update_result<U: TreapNodeUpdate<C>>(
        maybe_node: &mut Option<Box<Node<C>>>,
        result: OpResult<C, U::Ret, U::DeleteRet>,
    ) -> (U::Ret, bool, bool) {
        match result {
            OpResult::Noop(ret) => (ret, false, false),
            OpResult::Updated { update_weight, ret } => {
                (ret, update_weight, false)
            }
            OpResult::InsertOnVacant { insert, ret } => {
                // `maybe_node` should be empty here. So we ignore the replaced
                // value.
                let _ = mem::replace(maybe_node, Some(insert));
                (ret, true, true)
            }
            OpResult::Delete(delete_ret) => {
                let deleted_node = if maybe_node.is_some() {
                    Some(Node::delete(maybe_node))
                } else {
                    None
                };
                let ret = U::handle_delete(deleted_node, delete_ret);
                (ret, true, true)
            }
        }
    }

    // Rotate the current node to the leaf and delete it
    fn delete(mustbe_node: &mut Option<Box<Node<C>>>) -> Box<Self> {
        use Direction::*;
        let node = mustbe_node.as_mut().unwrap();
        let next_root = match (&node.left, &node.right) {
            (None, None) => {
                // Both is None, remove current node directly
                return mem::take(mustbe_node).unwrap();
            }
            (None, Some(_)) => Right,
            (Some(_), None) => Left,
            (Some(left), Some(right)) => {
                if left.priority < right.priority {
                    Right
                } else {
                    Left
                }
            }
        };

        let res = match next_root {
            Right => {
                // node.right must be `Some` before left rotate
                node.left_rotate();
                // node.left must be `Some` after left rotate
                Node::delete(&mut node.left)
            }
            Left => {
                // node.left must be `Some` before right rotate
                node.right_rotate();
                // node.right must be `Some` after right rotate
                Node::delete(&mut node.right)
            }
        };

        node.update_weight();
        res
    }

    //    X              Y
    //   / \            / \
    //  A   Y    <=    X   C
    //     / \        / \
    //    B   C      A   B

    fn right_rotate(self: &mut Box<Node<C>>) {
        //     Y  <- self
        //    / \
        //   X   C
        //  / \
        // A   B

        let y_node = self;
        let mut x_node = mem::take(&mut y_node.left).unwrap();

        //    Y  <- self      X
        //   / \             / \
        //  .   C           A   B

        // For efficiency, must swap pointer, instead of node data
        mem::swap::<Box<Node<C>>>(y_node, &mut x_node);
        let (x_node, mut y_node) = (y_node, x_node);

        //    Y               X  <- self
        //   / \             / \
        //  .   C           A   B

        mem::swap::<Option<Box<Node<C>>>>(&mut x_node.right, &mut y_node.left);

        //    Y               X  <- self
        //   / \             / \
        //  B   C           A   .

        y_node.update_weight();
        x_node.right = Some(y_node);

        //    X
        //   / \
        //  A   Y
        //     / \
        //    B   C

        x_node.update_weight();
    }

    //    X              Y
    //   / \            / \
    //  A   Y    =>    X   C
    //     / \        / \
    //    B   C      A   B
    fn left_rotate(self: &mut Box<Node<C>>) {
        //    X   <- self
        //   / \
        //  A   Y
        //     / \
        //    B   C

        let x_node = self;
        let mut y_node = mem::take(&mut x_node.right).unwrap();

        //    X  <- self      Y
        //   / \             / \
        //  A   .           B   C

        // For efficiency, must swap pointer, instead of node data
        mem::swap::<Box<Node<C>>>(x_node, &mut y_node);
        // Also swap variable name
        let (y_node, mut x_node) = (x_node, y_node);

        //    X               Y  <- self
        //   / \             / \
        //  A   .           B   C

        mem::swap::<Option<Box<Node<C>>>>(&mut y_node.left, &mut x_node.right);

        //    X               Y  <- self
        //   / \             / \
        //  A   B           .   C

        x_node.update_weight();
        y_node.left = Some(x_node);

        //      Y  <- self
        //     / \
        //    X   C
        //   / \
        //  A   B

        y_node.update_weight();
    }

    pub(crate) fn update_weight(&mut self) {
        self.sum_weight = self.weight.clone();
        if let Some(left) = &self.left {
            self.sum_weight.accure(&left.sum_weight);
        }
        if let Some(right) = &self.right {
            self.sum_weight.accure(&right.sum_weight);
        }
    }

    pub fn sum_weight(&self) -> C::Weight { self.sum_weight.clone() }

    #[cfg(any(test, feature = "testonly_code"))]
    pub(crate) fn assert_consistency(&self)
    where C::Weight: Eq + std::fmt::Debug {
        let mut weight = self.weight.clone();

        if let Some(left) = self.left.as_ref() {
            weight.accure(&left.sum_weight);
            assert!(left.priority <= self.priority);
            left.assert_consistency();
            assert_eq!(
                C::next_node_dir(
                    (&left.sort_key, &left.key),
                    (&self.sort_key, &self.key)
                ),
                Some(Direction::Left)
            );
        }
        if let Some(right) = self.right.as_ref() {
            weight.accure(&right.sum_weight);
            assert!(right.priority <= self.priority);
            right.assert_consistency();
            assert_eq!(
                C::next_node_dir(
                    (&right.sort_key, &right.key),
                    (&self.sort_key, &self.key)
                ),
                Some(Direction::Right)
            );
        }

        assert_eq!(weight, self.sum_weight);
    }
}

impl<C: TreapMapConfig> MallocSizeOf for Node<C>
where
    C::SearchKey: MallocSizeOf,
    C::SortKey: MallocSizeOf,
    C::Value: MallocSizeOf,
    C::Weight: MallocSizeOf,
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.key.size_of(ops)
            + self.sort_key.size_of(ops)
            + self.value.size_of(ops)
            + self.weight.size_of(ops)
            + self.sum_weight.size_of(ops)
            + self.left.size_of(ops)
            + self.right.size_of(ops)
    }
}
