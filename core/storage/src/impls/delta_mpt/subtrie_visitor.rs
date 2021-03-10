// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SubTrieVisitor<'trie, 'db: 'trie> {
    root: CowNodeRef,

    trie_ref: &'trie MerklePatriciaTrie,
    db: ReturnAfterUse<'trie, ArcDeltaDbWrapper>,
    phantom: PhantomData<&'db ArcDeltaDbWrapper>,

    /// We use ReturnAfterUse because only one SubTrieVisitor(the deepest) can
    /// hold the mutable reference of owned_node_set.
    owned_node_set: ReturnAfterUse<'trie, OwnedNodeSet>,
}

type MerklePatriciaTrie = DeltaMpt;

impl<'trie> SubTrieVisitor<'trie, 'trie> {
    pub fn new(
        trie_ref: &'trie MerklePatriciaTrie, root: NodeRefDeltaMpt,
        owned_node_set: &'trie mut Option<OwnedNodeSet>,
    ) -> Result<Self>
    {
        Ok(Self {
            trie_ref,
            db: ReturnAfterUse::new_from_value(trie_ref.get_arc_db()?),
            phantom: PhantomData,
            root: CowNodeRef::new(
                root,
                owned_node_set.as_ref().unwrap(),
                trie_ref.get_mpt_id(),
            ),
            owned_node_set: ReturnAfterUse::new(owned_node_set),
        })
    }
}

impl<'trie, 'db: 'trie> SubTrieVisitor<'trie, 'db> {
    fn new_visitor_for_subtree<'a>(
        &'a mut self, child_node: NodeRefDeltaMpt,
    ) -> SubTrieVisitor<'a, 'db>
    where 'trie: 'a {
        let trie_ref = self.trie_ref;
        let cow_child_node = CowNodeRef::new(
            child_node,
            self.owned_node_set.get_ref(),
            self.trie_ref.get_mpt_id(),
        );
        SubTrieVisitor {
            trie_ref,
            db: ReturnAfterUse::<'a, ArcDeltaDbWrapper>::new_from_origin::<'trie>(
                &mut self.db,
            ),
            phantom: PhantomData,
            root: cow_child_node,
            owned_node_set: ReturnAfterUse::new_from_origin(
                &mut self.owned_node_set,
            ),
        }
    }

    pub fn get_trie_ref(&self) -> &'trie MerklePatriciaTrie { self.trie_ref }

    fn node_memory_manager(&self) -> &'trie DeltaMptsNodeMemoryManager {
        &self.get_trie_ref().get_node_memory_manager()
    }

    fn get_trie_node<'a>(
        &mut self, key: KeyPart, allocator_ref: AllocatorRefRefDeltaMpt<'a>,
    ) -> Result<
        Option<
            GuardedValue<
                Option<MutexGuard<'a, DeltaMptsCacheManager>>,
                &'a TrieNodeDeltaMpt,
            >,
        >,
    >
    where 'trie: 'a {
        let node_memory_manager = self.node_memory_manager();
        let cache_manager = node_memory_manager.get_cache_manager();
        let mut node_ref = self.root.node_ref.clone();
        let mut key = key;

        let mut db_load_count = 0;
        loop {
            let mut is_loaded_from_db = false;
            let trie_node = node_memory_manager
                .node_as_ref_with_cache_manager(
                    allocator_ref,
                    node_ref,
                    cache_manager,
                    &mut *self.db.get_mut().to_owned_read()?,
                    self.trie_ref.get_mpt_id(),
                    &mut is_loaded_from_db,
                )?;
            if is_loaded_from_db {
                db_load_count += 1;
            }
            match trie_node.walk::<access_mode::Read>(key) {
                WalkStop::Arrived => {
                    node_memory_manager.log_uncached_key_access(db_load_count);
                    let (guard, trie_node) = trie_node.into();
                    return Ok(Some(GuardedValue::new(guard, trie_node)));
                }
                WalkStop::Descent {
                    key_remaining,
                    child_index: _,
                    child_node,
                } => {
                    node_ref = child_node.clone().into();
                    key = key_remaining;
                }
                _ => {
                    return Ok(None);
                }
            }
        }
    }

    fn retrieve_children_hashes<'a>(
        &self, children_table: ChildrenTableDeltaMpt,
    ) -> Result<MaybeMerkleTable> {
        if children_table.get_children_count() == 0 {
            return Ok(None);
        }

        let mut merkles = ChildrenMerkleTable::default();

        for (i, maybe_node_ref) in children_table.iter_non_skip() {
            merkles[i as usize] = match maybe_node_ref {
                None => MERKLE_NULL_NODE,
                Some(node_ref) => {
                    self.trie_ref.get_merkle(Some((*node_ref).into()))?.unwrap()
                }
            };
        }

        return Ok(Some(merkles));
    }

    pub fn get_proof<'a>(&mut self, key: KeyPart) -> Result<TrieProof> {
        let allocator_ref = &self.node_memory_manager().get_allocator();
        let node_memory_manager = self.node_memory_manager();
        let cache_manager = node_memory_manager.get_cache_manager();

        let mut proof_nodes = vec![];
        let mut finished = false;
        let mut node_ref = self.root.node_ref.clone();
        let mut key = key;
        let mut path_without_first_nibble = false;

        while !finished {
            // retrieve current trie node
            let trie_node = node_memory_manager
                .node_as_ref_with_cache_manager(
                    allocator_ref,
                    node_ref.clone(),
                    cache_manager,
                    &mut *self.db.get_mut().to_owned_read()?,
                    self.trie_ref.get_mpt_id(),
                    &mut false,
                )?;

            // update variables for subsequent traversal
            match trie_node.walk::<access_mode::Read>(key) {
                WalkStop::Arrived => {
                    finished = true;
                }
                WalkStop::Descent {
                    key_remaining,
                    child_node,
                    ..
                } => {
                    node_ref = child_node.clone().into();
                    key = key_remaining;
                }
                _ => {
                    finished = true;
                }
            };

            // create proof node
            proof_nodes.push({
                let maybe_value = trie_node.value_clone().into_option();
                let compressed_path = trie_node.compressed_path_ref().into();

                let children = trie_node.children_table.clone();
                let this_node_path_without_first_nibble =
                    path_without_first_nibble;
                path_without_first_nibble =
                    CompressedPathRaw::has_second_nibble(
                        trie_node.compressed_path_ref().path_mask(),
                    );
                drop(trie_node);
                let children_merkles =
                    self.retrieve_children_hashes(children)?;
                TrieProofNode::new(
                    children_merkles.into(),
                    maybe_value,
                    compressed_path,
                    this_node_path_without_first_nibble,
                )
            });
        }

        // The proof can be wrong when the trie is being modified and we haven't
        // update the merkle hash bottom-up.
        Ok(TrieProof::new(proof_nodes)?)
    }

    pub fn get(&mut self, key: KeyPart) -> Result<MptValue<Box<[u8]>>> {
        let allocator = self.node_memory_manager().get_allocator();
        let maybe_trie_node = self.get_trie_node(key, &allocator)?;

        Ok(match maybe_trie_node {
            None => MptValue::None,
            Some(trie_node) => trie_node.value_clone(),
        })
    }

    pub fn get_merkle_hash_wo_compressed_path(
        &mut self, key: KeyPart,
    ) -> Result<Option<MerkleHash>> {
        let allocator = self.node_memory_manager().get_allocator();
        let maybe_trie_node = self.get_trie_node(key, &allocator)?;

        match maybe_trie_node {
            None => Ok(None),
            Some(trie_node) => {
                if trie_node.get_compressed_path_size() == 0 {
                    return Ok(Some(trie_node.get_merkle().clone()));
                }

                let maybe_value = trie_node.value_clone().into_option();

                let merkles = {
                    let children_table = trie_node.children_table.clone();
                    drop(trie_node);
                    self.retrieve_children_hashes(children_table)?
                };

                Ok(Some(compute_node_merkle(
                    merkles.as_ref(),
                    maybe_value.as_ref().map(|value| value.as_ref()),
                )))
            }
        }
    }

    /// The visitor can only be used once to modify.
    /// Returns (deleted value, is root node replaced, the current root node for
    /// the subtree).
    pub fn delete(
        mut self, key: KeyPart,
    ) -> Result<(Option<Box<[u8]>>, bool, Option<NodeRefDeltaMptCompact>)> {
        let node_memory_manager = self.node_memory_manager();
        let allocator = node_memory_manager.get_allocator();
        let mut node_cow = self.root.take();
        // TODO(yz): be compliant to borrow rule and avoid duplicated

        // FIXME: map_split?
        let is_owned = node_cow.is_owned();
        let trie_node_ref = node_cow.get_trie_node(
            node_memory_manager,
            &allocator,
            &mut *self.db.get_mut().to_owned_read()?,
        )?;
        match trie_node_ref.walk::<access_mode::Read>(key) {
            WalkStop::Arrived => {
                // If value doesn't exists, returns invalid key error.
                let result = trie_node_ref.check_delete_value();
                if result.is_err() {
                    return Ok((None, false, node_cow.into_child()));
                }
                let action = result.unwrap();
                match action {
                    TrieNodeAction::Delete => {
                        // The current node is going to be dropped if owned.
                        let trie_node = GuardedValue::take(trie_node_ref);
                        let value = unsafe {
                            node_cow.delete_value_unchecked_followed_by_node_deletion(
                                trie_node,
                            )
                        };
                        node_cow.delete_node(
                            node_memory_manager,
                            self.owned_node_set.get_mut(),
                        );
                        Ok((Some(value), true, None))
                    }
                    TrieNodeAction::MergePath {
                        child_index,
                        child_node_ref,
                    } => {
                        // The current node is going to be merged with its only
                        // child after the value deletion.
                        let value = trie_node_ref.value_clone().unwrap();

                        let trie_node = GuardedValue::take(trie_node_ref);
                        let merged_node_cow = node_cow.cow_merge_path(
                            self.get_trie_ref(),
                            self.owned_node_set.get_mut(),
                            trie_node,
                            child_node_ref,
                            child_index,
                            &mut *self.db.get_mut().to_owned_read()?,
                        )?;

                        // FIXME: true?
                        Ok((Some(value), true, merged_node_cow.into_child()))
                    }
                    TrieNodeAction::Modify => {
                        let node_changed = !is_owned;
                        let trie_node = GuardedValue::take(trie_node_ref);
                        let value = unsafe {
                            node_cow.cow_delete_value_unchecked(
                                &node_memory_manager,
                                self.owned_node_set.get_mut(),
                                trie_node,
                            )?
                        };

                        Ok((Some(value), node_changed, node_cow.into_child()))
                    }
                }
            }
            WalkStop::Descent {
                key_remaining,
                child_node,
                child_index,
            } => {
                drop(trie_node_ref);
                let result = self
                    .new_visitor_for_subtree(child_node.clone().into())
                    .delete(key_remaining);
                if result.is_err() {
                    node_cow.into_child();
                    return result;
                }
                let trie_node_ref = node_cow.get_trie_node(
                    node_memory_manager,
                    &allocator,
                    &mut *self.db.get_mut().to_owned_read()?,
                )?;
                let (value, child_replaced, new_child_node) = result.unwrap();
                if child_replaced {
                    let action = trie_node_ref
                        .check_replace_or_delete_child_action(
                            child_index,
                            new_child_node,
                        );
                    match action {
                        TrieNodeAction::MergePath {
                            child_index,
                            child_node_ref,
                        } => {
                            // The current node is going to be merged with its
                            // only child after the
                            // value deletion.
                            let trie_node = GuardedValue::take(trie_node_ref);
                            let merged_node_cow = node_cow.cow_merge_path(
                                self.get_trie_ref(),
                                self.owned_node_set.get_mut(),
                                trie_node,
                                child_node_ref,
                                child_index,
                                &mut *self.db.get_mut().to_owned_read()?,
                            )?;

                            // FIXME: true?
                            Ok((value, true, merged_node_cow.into_child()))
                        }
                        TrieNodeAction::Modify => unsafe {
                            let node_ref_changed = !is_owned;
                            let trie_node = GuardedValue::take(trie_node_ref);
                            match new_child_node {
                                None => {
                                    node_cow
                                        .cow_modify(
                                            &allocator,
                                            self.owned_node_set.get_mut(),
                                            trie_node,
                                        )?
                                        .delete_child_unchecked(child_index);
                                }
                                Some(replacement) => {
                                    node_cow
                                        .cow_modify(
                                            &allocator,
                                            self.owned_node_set.get_mut(),
                                            trie_node,
                                        )?
                                        .replace_child_unchecked(
                                            child_index,
                                            replacement,
                                        );
                                }
                            }

                            Ok((value, node_ref_changed, node_cow.into_child()))
                        },
                        _ => unsafe { unreachable_unchecked() },
                    }
                } else {
                    Ok((value, false, node_cow.into_child()))
                }
            }

            _ => Ok((None, false, node_cow.into_child())),
        }
    }

    /// The visitor can only be used once to modify.
    /// Returns (deleted value, is root node replaced, the current root node for
    /// the subtree).
    pub fn delete_all(
        mut self, key: KeyPart, key_remaining: KeyPart,
    ) -> Result<(
        Option<Vec<MptKeyValue>>,
        bool,
        Option<NodeRefDeltaMptCompact>,
    )> {
        let node_memory_manager = self.node_memory_manager();
        let allocator = node_memory_manager.get_allocator();
        let mut node_cow = self.root.take();
        // TODO(yz): be compliant to borrow rule and avoid duplicated

        // FIXME: map_split?
        let trie_node_ref = node_cow.get_trie_node(
            node_memory_manager,
            &allocator,
            &mut *self.db.get_mut().to_owned_read()?,
        )?;

        let key_prefix: CompressedPathRaw;
        match trie_node_ref.walk::<access_mode::Write>(key_remaining) {
            WalkStop::ChildNotFound {
                key_remaining: _,
                child_index: _,
            } => return Ok((None, false, node_cow.into_child())),
            WalkStop::Arrived => {
                // To enumerate the subtree.
                key_prefix = key.into();
            }
            WalkStop::PathDiverted {
                key_child_index,
                key_remaining: _,
                matched_path: _,
                unmatched_child_index,
                unmatched_path_remaining,
            } => {
                if key_child_index.is_some() {
                    return Ok((None, false, node_cow.into_child()));
                }
                // To enumerate the subtree.
                key_prefix = CompressedPathRaw::join_connected_paths(
                    &key,
                    unmatched_child_index,
                    &unmatched_path_remaining,
                );
            }
            WalkStop::Descent {
                key_remaining,
                child_node,
                child_index,
            } => {
                drop(trie_node_ref);
                let result = self
                    .new_visitor_for_subtree(child_node.clone().into())
                    .delete_all(key, key_remaining);
                if result.is_err() {
                    node_cow.into_child();
                    return result;
                }
                let is_owned = node_cow.is_owned();
                let trie_node_ref = node_cow.get_trie_node(
                    node_memory_manager,
                    &allocator,
                    &mut *self.db.get_mut().to_owned_read()?,
                )?;
                let (value, child_replaced, new_child_node) = result.unwrap();
                // FIXME: copied from delete(). Try to reuse code?
                if child_replaced {
                    let action = trie_node_ref
                        .check_replace_or_delete_child_action(
                            child_index,
                            new_child_node,
                        );
                    match action {
                        TrieNodeAction::MergePath {
                            child_index,
                            child_node_ref,
                        } => {
                            // The current node is going to be merged with its
                            // only child after the
                            // value deletion.
                            let trie_node = GuardedValue::take(trie_node_ref);
                            let merged_node_cow = node_cow.cow_merge_path(
                                self.get_trie_ref(),
                                self.owned_node_set.get_mut(),
                                trie_node,
                                child_node_ref,
                                child_index,
                                &mut *self.db.get_mut().to_owned_read()?,
                            )?;

                            // FIXME: true?
                            return Ok((
                                value,
                                true,
                                merged_node_cow.into_child(),
                            ));
                        }
                        TrieNodeAction::Modify => unsafe {
                            let node_ref_changed = !is_owned;
                            let trie_node = GuardedValue::take(trie_node_ref);
                            match new_child_node {
                                None => {
                                    node_cow
                                        .cow_modify(
                                            &allocator,
                                            self.owned_node_set.get_mut(),
                                            trie_node,
                                        )?
                                        .delete_child_unchecked(child_index);
                                }
                                Some(replacement) => {
                                    node_cow
                                        .cow_modify(
                                            &allocator,
                                            self.owned_node_set.get_mut(),
                                            trie_node,
                                        )?
                                        .replace_child_unchecked(
                                            child_index,
                                            replacement,
                                        );
                                }
                            }

                            return Ok((
                                value,
                                node_ref_changed,
                                node_cow.into_child(),
                            ));
                        },
                        _ => unsafe { unreachable_unchecked() },
                    }
                } else {
                    return Ok((value, false, node_cow.into_child()));
                }
            }
        }

        let trie_node = GuardedValue::take(trie_node_ref);
        let mut old_values = vec![];
        node_cow.delete_subtree(
            self.get_trie_ref(),
            self.owned_node_set.get_ref(),
            trie_node,
            key_prefix,
            &mut old_values,
            &mut *self.db.get_mut().to_owned_read()?,
        )?;

        Ok((Some(old_values), true, None))
    }

    /// return all key/value pairs given the prefix
    pub fn traversal(
        mut self, key: KeyPart, key_remaining: KeyPart,
    ) -> Result<Option<Vec<MptKeyValue>>> {
        let node_memory_manager = self.node_memory_manager();
        let allocator = node_memory_manager.get_allocator();
        let mut node_cow = self.root.take();

        let trie_node_ref = node_cow.get_trie_node(
            node_memory_manager,
            &allocator,
            &mut *self.db.get_mut().to_owned_read()?,
        )?;

        let key_prefix: CompressedPathRaw;
        match trie_node_ref.walk::<access_mode::Write>(key_remaining) {
            WalkStop::ChildNotFound { .. } => return Ok(None),
            WalkStop::Arrived => {
                // To enumerate the subtree.
                key_prefix = key.into();
            }
            WalkStop::PathDiverted {
                key_child_index,
                unmatched_child_index,
                unmatched_path_remaining,
                ..
            } => {
                if key_child_index.is_some() {
                    return Ok(None);
                }
                // To enumerate the subtree.
                key_prefix = CompressedPathRaw::join_connected_paths(
                    &key,
                    unmatched_child_index,
                    &unmatched_path_remaining,
                );
            }
            WalkStop::Descent {
                key_remaining,
                child_node,
                ..
            } => {
                drop(trie_node_ref);
                let values = self
                    .new_visitor_for_subtree(child_node.clone().into())
                    .traversal(key, key_remaining)?;
                return Ok(values);
            }
        }

        let trie_node = GuardedValue::take(trie_node_ref);
        let mut values = vec![];
        node_cow.iterate_internal(
            self.owned_node_set.get_ref(),
            self.get_trie_ref(),
            trie_node,
            key_prefix,
            &mut values,
            &mut *self.db.get_mut().to_owned_read()?,
        )?;
        Ok(Some(values))
    }

    // In a method we visit node one or 2 times but borrow-checker prevent
    // holding and access other fields so it's visited multiple times.
    // FIXME: Check if we did something like this.
    // It's correct behavior if we first
    // access this node, recurse into children, then access it again, because
    // the accesses in subtree and other threads may in extreme cases evict
    // this node from cache.

    // Assume that the obtained TrieNode will be set valid value (non-empty)
    // later on.
    /// Insert a valid value into MPT.
    /// The visitor can only be used once to modify.
    unsafe fn insert_checked_value(
        mut self, key: KeyPart, value: Box<[u8]>,
    ) -> Result<(bool, NodeRefDeltaMptCompact)> {
        let node_memory_manager = self.node_memory_manager();
        let allocator = node_memory_manager.get_allocator();
        let mut node_cow = self.root.take();
        // TODO(yz): be compliant to borrow rule and avoid duplicated

        let is_owned = node_cow.is_owned();
        // FIXME: apply db_load_counter to all places where it matters, and also
        // FIXME: pass down to recursion. (Also check other methods.)
        let trie_node_ref = node_cow.get_trie_node(
            node_memory_manager,
            &allocator,
            &mut *self.db.get_mut().to_owned_read()?,
        )?;
        match trie_node_ref.walk::<access_mode::Write>(key) {
            WalkStop::Arrived => {
                let node_ref_changed = !is_owned;
                let trie_node = GuardedValue::take(trie_node_ref);
                node_cow.cow_replace_value_valid(
                    &node_memory_manager,
                    self.owned_node_set.get_mut(),
                    trie_node,
                    value,
                )?;

                Ok((node_ref_changed, node_cow.into_child().unwrap()))
            }
            WalkStop::Descent {
                key_remaining,
                child_node,
                child_index,
            } => {
                drop(trie_node_ref);
                let result = self
                    .new_visitor_for_subtree(child_node.clone().into())
                    .insert_checked_value(key_remaining, value);
                if result.is_err() {
                    node_cow.into_child();
                    return result;
                }
                let (child_changed, new_child_node) = result.unwrap();

                if child_changed {
                    let node_ref_changed = !node_cow.is_owned();
                    let trie_node =
                        GuardedValue::take(node_cow.get_trie_node(
                            node_memory_manager,
                            &allocator,
                            &mut *self.db.get_mut().to_owned_read()?,
                        )?);
                    node_cow
                        .cow_modify(
                            &allocator,
                            self.owned_node_set.get_mut(),
                            trie_node,
                        )?
                        .replace_child_unchecked(child_index, new_child_node);

                    Ok((node_ref_changed, node_cow.into_child().unwrap()))
                } else {
                    Ok((false, node_cow.into_child().unwrap()))
                }
            }
            WalkStop::PathDiverted {
                key_child_index,
                key_remaining,
                matched_path,
                unmatched_child_index,
                unmatched_path_remaining,
            } => {
                // create a new node to replace self with compressed
                // path = matched_path, modify current
                // node with the remaining path, and attach it as child to the
                // replacement node create a new node for
                // insertion (if key_remaining is non-empty), set it to child,
                // with key_remaining.
                let (new_node_cow, new_node_entry) =
                    CowNodeRef::new_uninitialized_node(
                        &allocator,
                        self.owned_node_set.get_mut(),
                        self.trie_ref.get_mpt_id(),
                    )?;
                let mut new_node = MemOptimizedTrieNode::default();
                // set compressed path.
                new_node.set_compressed_path(matched_path);

                let trie_node = GuardedValue::take(trie_node_ref);
                node_cow.cow_set_compressed_path(
                    &node_memory_manager,
                    self.owned_node_set.get_mut(),
                    unmatched_path_remaining,
                    trie_node,
                )?;

                // It's safe because we know that this is the first child.
                new_node.set_first_child_unchecked(
                    unmatched_child_index,
                    // It's safe to unwrap because we know that it's not none.
                    node_cow.into_child().unwrap(),
                );

                // TODO(yz): remove duplicated code.
                match key_child_index {
                    None => {
                        // Insert value at the current node
                        new_node.replace_value_valid(value);
                    }
                    Some(child_index) => {
                        // TODO(yz): Maybe create CowNodeRef on NULL then
                        // cow_set_value then set path.
                        let (child_node_cow, child_node_entry) =
                            CowNodeRef::new_uninitialized_node(
                                &allocator,
                                self.owned_node_set.get_mut(),
                                self.trie_ref.get_mpt_id(),
                            )?;
                        let mut new_child_node =
                            MemOptimizedTrieNode::default();
                        // set compressed path.
                        new_child_node.copy_compressed_path(key_remaining);
                        new_child_node.replace_value_valid(value);
                        child_node_entry.insert(&new_child_node);

                        // It's safe because it's guaranteed that
                        // key_child_index != unmatched_child_index
                        new_node.add_new_child_unchecked(
                            child_index,
                            // It's safe to unwrap here because it's not null
                            // node.
                            child_node_cow.into_child().unwrap(),
                        );
                    }
                }
                new_node_entry.insert(&new_node);
                Ok((true, new_node_cow.into_child().unwrap()))
            }
            WalkStop::ChildNotFound {
                key_remaining,
                child_index,
            } => {
                // TODO(yz): Maybe create CowNodeRef on NULL then cow_set_value
                // then set path.
                let (child_node_cow, child_node_entry) =
                    CowNodeRef::new_uninitialized_node(
                        &allocator,
                        self.owned_node_set.get_mut(),
                        self.trie_ref.get_mpt_id(),
                    )?;
                let mut new_child_node = MemOptimizedTrieNode::default();
                // set compressed path.
                new_child_node.copy_compressed_path(key_remaining);
                new_child_node.replace_value_valid(value);
                child_node_entry.insert(&new_child_node);

                let node_ref_changed = !is_owned;
                let trie_node = GuardedValue::take(trie_node_ref);
                node_cow
                    .cow_modify(
                        &allocator,
                        self.owned_node_set.get_mut(),
                        trie_node,
                    )?
                    .add_new_child_unchecked(
                        child_index,
                        child_node_cow.into_child().unwrap(),
                    );

                Ok((node_ref_changed, node_cow.into_child().unwrap()))
            }
        }
    }

    pub fn set(
        self, key: KeyPart, value: Box<[u8]>,
    ) -> Result<NodeRefDeltaMpt> {
        TrieNodeDeltaMpt::check_key_size(key)?;
        TrieNodeDeltaMpt::check_value_size(&value)?;
        let new_root;
        unsafe {
            new_root = self.insert_checked_value(key, value)?.1;
        }
        Ok(new_root.into())
    }
}

use super::{
    super::{
        super::utils::{access_mode, guarded_value::GuardedValue},
        errors::*,
        merkle_patricia_trie::{
            merkle::*,
            trie_proof::TrieProofNode,
            walk::{KeyPart, TrieNodeWalkTrait, WalkStop},
            *,
        },
    },
    cow_node_ref::CowNodeRef,
    delta_mpt_open_db_manager::ArcDeltaDbWrapper,
    mem_optimized_trie_node::*,
    node_memory_manager::*,
    owned_node_set::OwnedNodeSet,
    return_after_use::ReturnAfterUse,
    ChildrenTableDeltaMpt, DeltaMpt, *,
};
use parking_lot::MutexGuard;
use primitives::{MerkleHash, MptValue, MERKLE_NULL_NODE};
use std::{hint::unreachable_unchecked, marker::PhantomData};
