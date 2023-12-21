use super::{config::TreapMapConfig, node::Node};

///  The interface for insert/update/delete a node in a `Treap` by key by custom
/// logic.
pub trait TreapNodeUpdate<C: TreapMapConfig> {
    /// The return value
    type Ret;

    /// Retrieve the key of the node to be updated.
    fn treap_key(&self) -> (&C::SortKey, &C::SearchKey);

    /// The core update logic for a node.
    ///
    /// We pass `Option<&mut Box<_>>` instead of `&mut Option<Box<_>>` here
    /// intensionally. This approach restricts the function from directly
    /// inserting or removing nodes. Instead, the function should
    /// communicates any attempts to add or remove nodes through
    /// the `UpdateResult`.
    fn update_node(
        self, maybe_node: Option<&mut Box<Node<C>>>,
    ) -> UpdateResult<C, Self::Ret>;

    /// When a node needs to be deleted during an update, the deleted node will
    /// be fed to this method. The deletion logic itself is managed by
    /// `update_inner`.
    fn handle_delete(deleted_node: Option<Box<Node<C>>>) -> Self::Ret;
}

pub enum UpdateResult<C: TreapMapConfig, R> {
    /// Used when the targeted slot in the Treap is vacant and a new node
    /// should be inserted at this position.
    InsertOnVacant { insert: Box<Node<C>>, ret: R },
    /// Used when the targeted node been updated or remains unchanged.
    /// `update_weight` is a flag to indicate whether the weight of the node
    /// has changed as a result of the update. `ret` is the return value
    /// associated with this operation.
    ///
    /// ⚠️ WARNING: The update operation must not change the sort key of the
    /// node.
    Updated { update_weight: bool, ret: R },
    /// Used when the targeted node should be deleted.
    Delete,
}

pub(crate) struct InsertOp<C: TreapMapConfig>(pub Node<C>);

impl<C: TreapMapConfig> TreapNodeUpdate<C> for InsertOp<C> {
    type Ret = Option<C::Value>;

    fn treap_key(&self) -> (&C::SortKey, &C::SearchKey) {
        (&self.0.sort_key, &self.0.key)
    }

    fn update_node(
        self, maybe_node: Option<&mut Box<Node<C>>>,
    ) -> UpdateResult<C, Self::Ret> {
        use UpdateResult::*;

        if let Some(node) = maybe_node {
            let ret = Some(self.0.value.clone());
            let update_weight = node.weight != self.0.weight;

            node.value = self.0.value;
            node.weight = self.0.weight;

            Updated { ret, update_weight }
        } else {
            InsertOnVacant {
                insert: Box::new(self.0),
                ret: None,
            }
        }
    }

    fn handle_delete(_deleted_node: Option<Box<Node<C>>>) -> Self::Ret {
        // update_node never returns deletion
        unreachable!()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RemoveOp<'a, C: TreapMapConfig>(
    pub (&'a C::SortKey, &'a C::SearchKey),
);

impl<'a, C: TreapMapConfig> TreapNodeUpdate<C> for RemoveOp<'a, C> {
    type Ret = Option<C::Value>;

    fn treap_key(&self) -> (&C::SortKey, &C::SearchKey) { self.0 }

    fn update_node(
        self, _maybe_node: Option<&mut Box<Node<C>>>,
    ) -> UpdateResult<C, Self::Ret> {
        UpdateResult::Delete
    }

    fn handle_delete(deleted_node: Option<Box<Node<C>>>) -> Self::Ret {
        deleted_node.map(|x| x.value)
    }
}
