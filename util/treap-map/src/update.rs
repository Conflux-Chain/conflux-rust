use crate::KeyMngTrait;

use super::{config::TreapMapConfig, node::Node};

///  The interface for insert/update/delete a node in a `Treap` by key by custom
/// logic.
pub trait TreapNodeUpdate<C: TreapMapConfig> {
    /// The return value
    type Ret;
    /// The return value if delete is required.
    type DeleteRet;

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
    ) -> OpResult<C, Self::Ret, Self::DeleteRet>;

    /// When a node needs to be deleted during an update, the deleted node will
    /// be fed to this method. The deletion logic itself is managed by
    /// `update_inner`.
    fn handle_delete(
        deleted_node: Option<Box<Node<C>>>, delete_ret: Self::DeleteRet,
    ) -> Self::Ret;
}

pub enum OpResult<C: TreapMapConfig, R, DR> {
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
    /// Used when the targeted node is not changed. Equivalent to `Updated`
    /// with `update_weight = false`
    Noop(R),
    /// Used when the targeted node should be deleted.
    Delete(DR),
}

pub(crate) struct InsertOp<'a, C: TreapMapConfig> {
    pub node: Box<Node<C>>,
    pub ext_map: &'a mut C::ExtMap,
}

impl<'a, C: TreapMapConfig> TreapNodeUpdate<C> for InsertOp<'a, C> {
    type DeleteRet = ();
    type Ret = Option<C::Value>;

    fn treap_key(&self) -> (&C::SortKey, &C::SearchKey) {
        (&self.node.sort_key, &self.node.key)
    }

    fn update_node(
        self, maybe_node: Option<&mut Box<Node<C>>>,
    ) -> OpResult<C, Self::Ret, Self::DeleteRet> {
        use OpResult::*;

        if let Some(node) = maybe_node {
            let ret = Some(node.value.clone());
            let update_weight = node.weight != self.node.weight;

            self.ext_map.view_update(
                &self.node.key,
                Some(&self.node.value),
                Some(&node.value),
            );

            node.value = self.node.value;
            node.weight = self.node.weight;

            Updated { ret, update_weight }
        } else {
            self.ext_map.view_update(
                &self.node.key,
                Some(&self.node.value),
                None,
            );
            InsertOnVacant {
                insert: self.node,
                ret: None,
            }
        }
    }

    fn handle_delete(
        _deleted_node: Option<Box<Node<C>>>, _delete_ret: (),
    ) -> Self::Ret {
        // update_node never returns deletion
        unreachable!()
    }
}

pub(crate) struct RemoveOp<'a, C: TreapMapConfig> {
    pub key: (&'a C::SortKey, &'a C::SearchKey),
    pub ext_map: &'a mut C::ExtMap,
}

impl<'a, C: TreapMapConfig> TreapNodeUpdate<C> for RemoveOp<'a, C> {
    type DeleteRet = ();
    type Ret = Option<C::Value>;

    fn treap_key(&self) -> (&C::SortKey, &C::SearchKey) { self.key }

    fn update_node(
        self, maybe_node: Option<&mut Box<Node<C>>>,
    ) -> OpResult<C, Self::Ret, Self::DeleteRet> {
        self.ext_map.view_update(
            self.key.1,
            None,
            maybe_node.map(|x| &x.value),
        );
        OpResult::Delete(())
    }

    fn handle_delete(
        deleted_node: Option<Box<Node<C>>>, _delete_ret: (),
    ) -> Self::Ret {
        deleted_node.map(|x| x.value)
    }
}

pub struct ApplyOpOutcome<T> {
    pub out: T,
    pub update_weight: bool,
    pub update_key: bool,
}

pub(crate) struct ApplyOp<'a, C, U, I, T, E>
where
    C: TreapMapConfig,
    U: FnOnce(&mut Node<C>) -> Result<ApplyOpOutcome<T>, E>,
    I: FnOnce() -> Result<(Node<C>, T), E>,
{
    pub key: (&'a C::SortKey, &'a C::SearchKey),
    pub ext_map: &'a mut C::ExtMap,
    pub update: U,
    pub insert: I,
}

impl<'a, 'b, C, U, I, T, E> TreapNodeUpdate<C> for ApplyOp<'a, C, U, I, T, E>
where
    C: TreapMapConfig,
    U: FnOnce(&mut Node<C>) -> Result<ApplyOpOutcome<T>, E>,
    I: FnOnce() -> Result<(Node<C>, T), E>,
{
    type DeleteRet = T;
    type Ret = Result<(T, Option<Box<Node<C>>>), E>;

    fn treap_key(&self) -> (&'a C::SortKey, &'a C::SearchKey) { self.key }

    fn update_node(
        self, maybe_node: Option<&mut Box<Node<C>>>,
    ) -> OpResult<C, Self::Ret, Self::DeleteRet> {
        use OpResult::*;
        match maybe_node {
            None => {
                let (node, ret) = match (self.insert)() {
                    Ok(x) => x,
                    Err(err) => {
                        return Noop(Err(err));
                    }
                };

                self.ext_map
                    .view_update(&*self.key.1, Some(&node.value), None);
                assert!(
                    C::next_node_dir(self.key, (&node.sort_key, &node.key))
                        .is_none(),
                    "Inserted node has incosistent key"
                );
                InsertOnVacant {
                    insert: Box::new(node),
                    ret: Ok((ret, None)),
                }
            }
            Some(node) => {
                let old_value = node.value.clone();
                let ApplyOpOutcome {
                    out,
                    update_weight,
                    update_key,
                } = match (self.update)(node) {
                    Ok(x) => x,
                    Err(err) => {
                        return Noop(Err(err));
                    }
                };
                self.ext_map.view_update(
                    &*self.key.1,
                    Some(&node.value),
                    Some(&old_value),
                );

                if update_key {
                    Delete(out)
                } else {
                    Updated {
                        update_weight,
                        ret: Ok((out, None)),
                    }
                }
            }
        }
    }

    fn handle_delete(
        deleted_node: Option<Box<Node<C>>>, delete_ret: T,
    ) -> Self::Ret {
        Ok((delete_ret, Some(deleted_node.unwrap())))
    }
}
