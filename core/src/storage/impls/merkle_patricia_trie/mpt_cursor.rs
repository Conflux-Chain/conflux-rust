// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Cursor to access Snapshot Mpt.
pub struct MptCursor<Mpt, PathNode> {
    mpt: Option<Mpt>,
    path_nodes: Vec<PathNode>,
}

impl<Mpt, PathNode> MptCursor<Mpt, PathNode> {
    pub fn new(mpt: Mpt) -> Self {
        Self {
            mpt: Some(mpt),
            path_nodes: vec![],
        }
    }

    pub fn get_path_nodes(&self) -> &Vec<PathNode> { &self.path_nodes }

    /// Never call this method after pop_root.
    pub fn current_node_mut(&mut self) -> &mut PathNode {
        self.path_nodes.last_mut().unwrap()
    }
}

impl<Mpt: GetReadMpt, PathNode: PathNodeTrait<Mpt>> MptCursor<Mpt, PathNode> {
    pub fn load_root(&mut self) -> Result<()>
    where Self: CursorToRootNode<Mpt, PathNode> {
        let root_node = PathNode::load_root(self)?;
        self.path_nodes.push(root_node);
        Ok(())
    }

    pub fn to_proof(&self) -> TrieProof {
        let mut trie_nodes = Vec::with_capacity(self.path_nodes.len());
        for node in &self.path_nodes {
            let trie_node = &node.get_basic_path_node().trie_node;
            trie_nodes.push(TrieProofNode::new(
                trie_node.get_children_merkles().map_or_else(
                    || VanillaChildrenTable::default(),
                    |merkle_table| merkle_table.into(),
                ),
                trie_node
                    .value_as_slice()
                    .into_option()
                    .map(|slice| slice.into()),
                trie_node.compressed_path_ref().into(),
            ))
        }

        // Unwrap is fine because the TrieProof must be valid unless the Mpt is
        // being modified.
        TrieProof::new(trie_nodes).unwrap()
    }

    pub fn push_node(&mut self, node: PathNode) { self.path_nodes.push(node); }

    /// Don't call this method for root node.
    pub fn pop_one_node(&mut self) -> Result<()> {
        let node = self.path_nodes.pop().unwrap();
        let parent_node = self.path_nodes.last_mut().unwrap();
        let mpt_taken = node.commit(parent_node)?;
        let parent_basic_node = parent_node.get_basic_path_node_mut();
        parent_basic_node.next_child_index += 1;
        parent_basic_node.mpt = mpt_taken;

        Ok(())
    }

    fn pop_nodes(&mut self, target_key_steps: u16) -> Result<()> {
        // unwrap is fine because the first node is root and it will never be
        // popped.
        while self
            .path_nodes
            .last()
            .unwrap()
            .get_basic_path_node()
            .path_start_steps
            > target_key_steps
        {
            self.pop_one_node()?
        }
        Ok(())
    }

    fn pop_root(&mut self) -> Result<MerkleHash> {
        self.path_nodes.pop().unwrap().commit_root(&mut self.mpt)
    }

    pub fn finish(&mut self) -> Result<MerkleHash> {
        self.pop_nodes(0)?;
        self.pop_root()
    }

    /// Pop irrelevant paths and calculate what's remaining.
    pub fn pop_path_for_key<'k, AM: access_mode::AccessMode>(
        &mut self, key: &'k [u8],
    ) -> Result<CursorPopNodesTerminal<'k>> {
        match walk::<access_mode::Write, _>(
            key,
            &self
                .path_nodes
                .last()
                .unwrap()
                .get_basic_path_node()
                .full_path_to_node,
            &MPT_CURSOR_GET_CHILD,
        ) {
            WalkStop::Arrived => Ok(CursorPopNodesTerminal::Arrived),
            // The scenario of Descent is classified into ChildNotFound scenario
            // because the checking of child_index is skipped.
            WalkStop::Descent {
                child_index: _,
                key_remaining: _,
                child_node: _,
            } => unsafe { unreachable_unchecked() },
            // It actually means to descent.
            WalkStop::ChildNotFound {
                child_index,
                key_remaining,
            } => Ok(CursorPopNodesTerminal::Descent {
                child_index,
                key_remaining,
            }),
            WalkStop::PathDiverted {
                key_child_index,
                key_remaining,
                matched_path,
                unmatched_child_index,
                unmatched_path_remaining,
            } => {
                // Pop irrelevant nodes.
                let match_stopped_steps = matched_path.path_steps();
                self.pop_nodes(match_stopped_steps)?;

                let last_node = self.path_nodes.last().unwrap();
                let started_steps =
                    last_node.get_basic_path_node().path_start_steps;
                let last_trie_node = &last_node.get_basic_path_node().trie_node;

                // The beginning of compressed_path is always aligned at full
                // byte.
                let aligned_path_start_offset = started_steps / 2;
                if aligned_path_start_offset * 2
                    + last_trie_node.compressed_path_ref().path_steps()
                    == match_stopped_steps
                {
                    if key_child_index.is_none() {
                        // Arrived
                        Ok(CursorPopNodesTerminal::Arrived)
                    } else {
                        Ok(CursorPopNodesTerminal::Descent {
                            child_index: key_child_index.unwrap(),
                            key_remaining,
                        })
                    }
                } else {
                    // PathDiverted
                    if AM::is_read_only() {
                        Ok(CursorPopNodesTerminal::PathDiverted(
                            WalkStop::path_diverted_uninitialized(),
                        ))
                    } else {
                        let actual_matched_path = CompressedPathRaw::new(
                            &matched_path.path_slice()
                                [aligned_path_start_offset as usize..],
                            matched_path.end_mask(),
                        );
                        let original_compressed_path_ref =
                            last_trie_node.compressed_path_ref();
                        let actual_unmatched_path_remaining =
                            if original_compressed_path_ref.end_mask() != 0 {
                                CompressedPathRaw::new_and_apply_mask(
                                    &unmatched_path_remaining.path_slice()[0
                                        ..(original_compressed_path_ref
                                            .path_size()
                                            - actual_matched_path.path_size())
                                            as usize],
                                    original_compressed_path_ref.end_mask(),
                                )
                            } else {
                                CompressedPathRaw::new(
                                    &unmatched_path_remaining.path_slice()[0
                                        ..(original_compressed_path_ref
                                            .path_size()
                                            - actual_matched_path.path_size())
                                            as usize],
                                    original_compressed_path_ref.end_mask(),
                                )
                            };

                        Ok(CursorPopNodesTerminal::PathDiverted(
                            WalkStop::PathDiverted {
                                key_child_index,
                                key_remaining,
                                matched_path: actual_matched_path,
                                unmatched_child_index,
                                unmatched_path_remaining:
                                    actual_unmatched_path_remaining,
                            },
                        ))
                    }
                }
            }
        }
    }

    pub fn open_path_for_key<'k, AM: access_mode::AccessMode>(
        &mut self, key: &'k [u8],
    ) -> Result<CursorOpenPathTerminal<'k>> {
        // The access_mode is Write here because we need the diverted path
        // information.
        match self.pop_path_for_key::<access_mode::Write>(key) {
            Err(e) => Err(e),
            Ok(CursorPopNodesTerminal::Arrived) => {
                Ok(CursorOpenPathTerminal::Arrived)
            }
            Ok(CursorPopNodesTerminal::PathDiverted(path_diverted)) => {
                Ok(CursorOpenPathTerminal::PathDiverted(path_diverted))
            }
            Ok(CursorPopNodesTerminal::Descent {
                mut key_remaining,
                mut child_index,
            }) => {
                loop {
                    let new_node = match self
                        .path_nodes
                        .last_mut()
                        .unwrap()
                        .open_child_index(child_index)?
                    {
                        Some(node) => node,
                        None => {
                            return Ok(CursorOpenPathTerminal::ChildNotFound {
                                key_remaining,
                                child_index,
                            })
                        }
                    };

                    let next_step = walk::<AM, _>(
                        key_remaining,
                        &new_node
                            .get_basic_path_node()
                            .trie_node
                            .compressed_path_ref(),
                        &MPT_CURSOR_GET_CHILD,
                    );
                    match &next_step {
                        WalkStop::Arrived => {
                            self.path_nodes.push(new_node);
                            return Ok(CursorOpenPathTerminal::Arrived);
                        }
                        // The scenario of Descent is classified into
                        // ChildNotFound scenario because the checking of
                        // child_index is skipped.
                        WalkStop::Descent { .. } => unsafe {
                            unreachable_unchecked()
                        },
                        // It actually means to descent.
                        WalkStop::ChildNotFound {
                            child_index: new_child_index,
                            key_remaining: new_key_remaining,
                        } => {
                            self.path_nodes.push(new_node);
                            child_index = *new_child_index;
                            key_remaining = *new_key_remaining;
                            continue;
                        }
                        WalkStop::PathDiverted { .. } => {
                            self.path_nodes.push(new_node);
                            // Leave the match to save the path_diverted
                            // information, then break the loop to finally
                            // work on the expanding of compressed path.
                        }
                    }
                    return Ok(CursorOpenPathTerminal::PathDiverted(next_step));
                }
            }
        }
    }
}

pub struct MptCursorRw<Mpt, RwPathNode> {
    cursor: MptCursor<Mpt, RwPathNode>,

    io_error: Cell<bool>,
}

impl<Mpt, RwPathNode> Deref for MptCursorRw<Mpt, RwPathNode> {
    type Target = MptCursor<Mpt, RwPathNode>;

    fn deref(&self) -> &Self::Target { &self.cursor }
}

impl<Mpt, RwPathNode> DerefMut for MptCursorRw<Mpt, RwPathNode> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.cursor }
}

impl<Mpt: GetRwMpt, PathNode: RwPathNodeTrait<Mpt>> MptCursorRw<Mpt, PathNode> {
    pub fn new(mpt: Mpt) -> Self {
        Self {
            cursor: MptCursor::new(mpt),
            io_error: Cell::new(false),
        }
    }

    pub fn load_root(&mut self) -> Result<()>
    where Self: CursorToRootNode<Mpt, PathNode> {
        let root_node = PathNode::load_root(self)?;
        self.path_nodes.push(root_node);
        Ok(())
    }

    pub fn insert(&mut self, key: &[u8], value: Box<[u8]>) -> Result<()> {
        match self.open_path_for_key::<access_mode::Write>(key)? {
            CursorOpenPathTerminal::Arrived => {
                self.path_nodes
                    .last_mut()
                    .unwrap()
                    .replace_value_valid(value);
            }
            CursorOpenPathTerminal::ChildNotFound {
                child_index,
                key_remaining,
            } => {
                // Create a new node for child_index, key_remaining
                // and value.
                let value_len = value.len();
                let parent_node = self.path_nodes.last_mut().unwrap();
                unsafe {
                    parent_node
                        .get_read_write_path_node()
                        .trie_node
                        .add_new_child_unchecked(
                            child_index,
                            &SubtreeMerkleWithSize::default(),
                        );
                }
                parent_node
                    .get_read_write_path_node()
                    .skip_till_child_index(child_index)?;
                parent_node.get_read_write_path_node().next_child_index =
                    child_index;
                let new_node = PathNode::new(
                    BasicPathNode::new(
                        SnapshotMptNode(VanillaTrieNode::new(
                            MERKLE_NULL_NODE,
                            Default::default(),
                            Some(value),
                            key_remaining.into(),
                        )),
                        parent_node.take_mpt(),
                        &parent_node
                            .get_read_write_path_node()
                            .full_path_to_node,
                        child_index,
                    ),
                    parent_node,
                    value_len,
                );
                self.path_nodes.push(new_node);
            }
            CursorOpenPathTerminal::PathDiverted(WalkStop::PathDiverted {
                key_child_index,
                key_remaining,
                matched_path,
                unmatched_child_index,
                unmatched_path_remaining,
            }) => {
                let last_node = self.path_nodes.pop().unwrap();
                let parent_node = self.path_nodes.last_mut().unwrap();

                let value_len = value.len();
                let insert_value_at_fork = key_child_index.is_none();
                let mut last_node_as_child = SubtreeMerkleWithSize::default();
                // Set the size of the original Snapshot mpt. When the update in
                // the subtree of last node is finished, The new mpt's subtree
                // size is computed from the subtree_size_delta, and the
                // subtree_size_delta is propogated upward.
                last_node_as_child.subtree_size = (last_node
                    .get_read_only_path_node()
                    .trie_node
                    .subtree_size(
                        last_node.get_read_only_path_node().get_path_to_node(),
                    ) as i64
                    - last_node.get_read_only_path_node().subtree_size_delta)
                    as u64;
                let mut fork_node = PathNode::new(
                    BasicPathNode::new(
                        SnapshotMptNode(VanillaTrieNode::new(
                            MERKLE_NULL_NODE,
                            VanillaChildrenTable::new_from_one_child(
                                unmatched_child_index,
                                &last_node_as_child,
                            ),
                            // The value isn't set when insert_value_at_fork
                            // because the compiler
                            // wants to make sure value isn't moved in the
                            // Some() match branch below.
                            None,
                            matched_path,
                        )),
                        None,
                        &parent_node.get_basic_path_node().full_path_to_node,
                        parent_node.get_basic_path_node().next_child_index,
                    ),
                    parent_node,
                    if insert_value_at_fork { value_len } else { 0 },
                );

                // "delete" last node when necessary, and create a new node for
                // the unmatched path.
                let mut unmatched_child_node = last_node
                    .unmatched_child_node_for_path_diversion(
                        CompressedPathRaw::extend_path(
                            &fork_node.get_basic_path_node().full_path_to_node,
                            unmatched_child_index,
                        ),
                        unmatched_path_remaining,
                    )?;

                // Unmatched path on the right hand side.
                if key_child_index.is_none()
                    || key_child_index.unwrap() < unmatched_child_index
                {
                    // The unmatched subtree is not yet opened for operations,
                    // so it's kept under maybe_compressed_path_split_child_*
                    // fields of the fork node and will be processed later.
                    fork_node.get_basic_path_node_mut().mpt =
                        unmatched_child_node.take_mpt();
                    fork_node
                        .get_read_write_path_node()
                        .maybe_compressed_path_split_child_index =
                        unmatched_child_index;
                    fork_node
                        .get_read_write_path_node()
                        .maybe_compressed_path_split_child_node =
                        Some(Box::new(unmatched_child_node));
                } else {
                    // Path forked on the right side, the update in the subtree
                    // of last_node has finished.
                    // Commit last_node with parent as fork_node.
                    fork_node.get_read_write_path_node().next_child_index =
                        unmatched_child_index;
                    fork_node.get_read_write_path_node().mpt =
                        unmatched_child_node
                            .commit(fork_node.get_read_write_path_node())?;
                }
                match key_child_index {
                    Some(child_index) => unsafe {
                        // Move on to the next child.
                        fork_node.get_read_write_path_node().next_child_index =
                            child_index;
                        fork_node
                            .get_read_write_path_node()
                            .trie_node
                            .add_new_child_unchecked(
                                child_index,
                                &SubtreeMerkleWithSize::default(),
                            );

                        let value_node = PathNode::new(
                            BasicPathNode::new(
                                SnapshotMptNode(VanillaTrieNode::new(
                                    MERKLE_NULL_NODE,
                                    Default::default(),
                                    Some(value),
                                    key_remaining.into(),
                                )),
                                fork_node.take_mpt(),
                                &fork_node
                                    .get_basic_path_node()
                                    .full_path_to_node,
                                child_index,
                            ),
                            &fork_node,
                            value_len,
                        );

                        self.path_nodes.push(fork_node);
                        self.path_nodes.push(value_node);
                    },
                    None => {
                        fork_node
                            .get_read_write_path_node()
                            .trie_node
                            .replace_value_valid(value);

                        self.path_nodes.push(fork_node);
                    }
                }
            }
            _ => unsafe { unreachable_unchecked() },
        }

        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        match self.open_path_for_key::<access_mode::Read>(key)? {
            CursorOpenPathTerminal::Arrived => {
                let last_node = self.path_nodes.last_mut().unwrap();
                if last_node.get_read_only_path_node().trie_node.has_value() {
                    last_node.delete_value_assumed_existence();
                // The action here is as simple as delete the value. It
                // seems tricky if there is no children left, or if
                // there is only one children left. Actually, the
                // deletion of a node value happens before all subtree
                // actions. The skip_till_child_index method will take
                // care of all children, the committing will take care
                // of path merge and node deletion.
                } else {
                    warn!(
                        "In MptCursorRw, non-existing key {:?} is asked to be deleted.",
                        key);
                }
            }
            CursorOpenPathTerminal::PathDiverted(_) => {
                warn!(
                    "In MptCursorRw, non-existing key {:?} is asked to be deleted.",
                    key);
            }
            CursorOpenPathTerminal::ChildNotFound { .. } => {
                warn!(
                    "In MptCursorRw, non-existing key {:?} is asked to be deleted.",
                    key);
            }
        }
        Ok(())
    }

    fn copy_subtree_without_root(
        subtree_root: &mut ReadWritePathNode<Mpt>,
    ) -> Result<()> {
        let (dest_mpt, source_mpt) = subtree_root
            .basic_node
            .mpt
            .as_mut_assumed_owner()
            .get_write_and_read_mpt();
        let mut iter =
            match source_mpt.unwrap().iterate_subtree_trie_nodes_without_root(
                &subtree_root.basic_node.full_path_to_node,
            ) {
                Err(e) => {
                    subtree_root.has_io_error.set_has_io_error();
                    bail!(e);
                }
                Ok(iter) => iter,
            };
        loop {
            if let Some((path, snapshot_mpt_node)) = match iter.next() {
                Err(e) => {
                    subtree_root.has_io_error.set_has_io_error();
                    bail!(e);
                }
                Ok(item) => item,
            } {
                let result = dest_mpt.write_node(&path, &snapshot_mpt_node);
                if result.is_err() {
                    subtree_root.has_io_error.set_has_io_error();
                    return result;
                }
                continue;
            }
            break;
        }
        Ok(())
    }
}

pub trait CursorLoadNodeWrapper<Mpt>: TakeMpt<Mpt> {
    fn load_node_wrapper<'a>(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode>;
}

impl<Mpt: GetReadMpt> CursorLoadNodeWrapper<Mpt> for BasicPathNode<Mpt> {
    fn load_node_wrapper<'a>(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode> {
        mpt.get_read_mpt()
            .load_node(path)?
            .ok_or(Error::from(ErrorKind::SnapshotMPTTrieNodeNotFound))
    }
}

impl<Mpt: GetReadMpt, PathNode> CursorLoadNodeWrapper<Mpt>
    for MptCursor<Mpt, PathNode>
{
    fn load_node_wrapper(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode> {
        mpt.get_read_mpt()
            .load_node(path)?
            .ok_or(Error::from(ErrorKind::SnapshotMPTTrieNodeNotFound))
    }
}

/// General implementation for ReadWrite path nodes and cursor.
impl<Mpt: GetReadMpt, T: CursorSetIoError + TakeMpt<Mpt>>
    CursorLoadNodeWrapper<Mpt> for T
{
    fn load_node_wrapper(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode> {
        match mpt.get_read_mpt().load_node(path) {
            Err(e) => {
                self.set_has_io_error();

                Err(e)
            }
            Ok(Some(node)) => Ok(node),
            Ok(None) => {
                self.set_has_io_error();

                Err(Error::from(ErrorKind::SnapshotMPTTrieNodeNotFound))
            }
        }
    }
}

pub trait CursorToRootNode<Mpt: GetReadMpt, PathNode: PathNodeTrait<Mpt>> {
    fn new_root(
        &self, basic_node: BasicPathNode<Mpt>, mpt_is_empty: bool,
    ) -> PathNode;
}

impl<Mpt: GetReadMpt, Cursor: CursorLoadNodeWrapper<Mpt>>
    CursorToRootNode<Mpt, BasicPathNode<Mpt>> for Cursor
{
    fn new_root(
        &self, basic_node: BasicPathNode<Mpt>, _mpt_is_empty: bool,
    ) -> BasicPathNode<Mpt> {
        basic_node
    }
}

impl<Mpt: GetRwMpt, Cursor: CursorLoadNodeWrapper<Mpt> + CursorSetIoError>
    CursorToRootNode<Mpt, ReadWritePathNode<Mpt>> for Cursor
{
    fn new_root(
        &self, basic_node: BasicPathNode<Mpt>, mpt_is_empty: bool,
    ) -> ReadWritePathNode<Mpt> {
        ReadWritePathNode {
            basic_node,
            is_loaded: !mpt_is_empty,
            maybe_first_realized_child_index:
                ReadWritePathNode::<Mpt>::NULL_CHILD_INDEX,
            the_first_child_if_pending: None,
            maybe_compressed_path_split_child_index:
                ReadWritePathNode::<Mpt>::NULL_CHILD_INDEX,
            maybe_compressed_path_split_child_node: None,
            subtree_size_delta: 0,
            delta_subtree_size: 0,
            has_io_error: self.io_error(),
            db_committed: false,
        }
    }
}

pub struct BasicPathNode<Mpt> {
    pub mpt: Option<Mpt>,

    pub trie_node: SnapshotMptNode,

    /// The fields below are necessary for loading the requested key / values.
    // path_start_steps is changed when compressed path changes happen, but it
    // doesn't matter because it only happens to node removed from current MPT
    // path.
    path_start_steps: u16,
    // full_path_to_node is changed when combining compressed path.
    // But changes doesn't matter because when it happens it's already
    // popped out from current MPT path.
    full_path_to_node: CompressedPathRaw,
    // The path_db_key changes when breaking a compressed path.
    // The path_db_key must be corrected before writing out the node.
    path_db_key: CompressedPathRaw,

    /// The next child index to look into.
    pub next_child_index: u8,
}

impl<Mpt> BasicPathNode<Mpt> {
    fn new(
        trie_node: SnapshotMptNode, mpt: Option<Mpt>,
        parent_path: &CompressedPathRaw, child_index: u8,
    ) -> Self
    {
        let full_path_to_node = CompressedPathRaw::join_connected_paths(
            parent_path,
            child_index,
            &trie_node.compressed_path_ref(),
        );

        let path_db_key =
            CompressedPathRaw::extend_path(parent_path, child_index);
        Self {
            mpt,
            trie_node,
            path_start_steps: path_db_key.path_steps(),
            full_path_to_node,
            path_db_key,
            next_child_index: 0,
        }
    }

    pub fn get_path_to_node(&self) -> &CompressedPathRaw {
        &self.full_path_to_node
    }
}

impl<Mpt> Deref for BasicPathNode<Mpt> {
    type Target = SnapshotMptNode;

    fn deref(&self) -> &Self::Target { &self.trie_node }
}

pub struct ReadWritePathNode<Mpt> {
    basic_node: BasicPathNode<Mpt>,

    is_loaded: bool,

    /// When the node has only one child and no value after operations in its
    /// subtree, the node should be combined with its child. We keep the
    /// child index to join the path.
    ///
    /// The node has only one child <==>
    /// maybe_first_realized_child_index != NULL_CHILD_INDEX &&
    /// the_first_child_if_pending.is_some()
    ///
    /// These two fields are maintained based on the concluded subtree so far.
    maybe_first_realized_child_index: u8,
    the_first_child_if_pending: Option<Box<ReadWritePathNode<Mpt>>>,

    /// If the node is created by breaking compressed_path of a node in the
    /// original mpt, a new child node is created for the remaining part of the
    /// compressed path with the original children table. We must keep the
    /// new child, since we may recurse into the subtree of the new child
    /// later.
    maybe_compressed_path_split_child_index: u8,
    maybe_compressed_path_split_child_node: Option<Box<ReadWritePathNode<Mpt>>>,

    /// For SnapshotMpt
    subtree_size_delta: i64,
    /// For DeltaMpt which is the difference between current snapshot and the
    /// parent snapshots.
    delta_subtree_size: u64,

    has_io_error: *const Cell<bool>,
    db_committed: bool,
}

impl<Mpt> Deref for ReadWritePathNode<Mpt> {
    type Target = BasicPathNode<Mpt>;

    fn deref(&self) -> &Self::Target { &self.basic_node }
}

impl<Mpt> DerefMut for ReadWritePathNode<Mpt> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.basic_node }
}

pub trait PathNodeTrait<Mpt: GetReadMpt>:
    CursorLoadNodeWrapper<Mpt> + Drop + Sized
{
    fn new_loaded(basic_node: BasicPathNode<Mpt>, parent_node: &Self) -> Self;

    /// A default no-op implementation to suppress compiler warnings
    /// about "patterns aren't allowed in methods without bodies"
    /// https://github.com/rust-lang/rust/issues/35203
    fn commit(mut self, _parent_node: &mut Self) -> Result<Option<Mpt>> {
        Ok(self.take_mpt())
    }

    /// A default no-op implementation to suppress compiler warnings
    /// about "patterns aren't allowed in methods without bodies"
    /// https://github.com/rust-lang/rust/issues/35203
    fn commit_root(
        mut self, mpt_taken: &mut Option<Mpt>,
    ) -> Result<MerkleHash> {
        *mpt_taken = self.take_mpt();
        Ok(self.get_basic_path_node().trie_node.get_merkle().clone())
    }

    fn get_basic_path_node(&self) -> &BasicPathNode<Mpt>;

    fn get_basic_path_node_mut(&mut self) -> &mut BasicPathNode<Mpt>;

    fn load_root<
        Cursor: CursorLoadNodeWrapper<Mpt> + CursorToRootNode<Mpt, Self>,
    >(
        cursor: &mut Cursor,
    ) -> Result<Self> {
        let mut mpt = cursor.take_mpt();
        // Special case for Genesis snapshot, where the mpt is an non-existence
        // db, to which the load_node_wrapper call fails.
        let mpt_is_empty;
        let root_trie_node = match cursor.load_node_wrapper(
            mpt.as_mut_assumed_owner(),
            &CompressedPathRaw::default(),
        ) {
            Ok(node) => {
                mpt_is_empty = false;

                node
            }
            Err(e) => match e.kind() {
                ErrorKind::SnapshotMPTTrieNodeNotFound => {
                    mpt_is_empty = true;

                    SnapshotMptNode(VanillaTrieNode::new(
                        MERKLE_NULL_NODE,
                        Default::default(),
                        None,
                        CompressedPathRaw::default(),
                    ))
                }
                _ => {
                    bail!(e);
                }
            },
        };

        Ok(cursor.new_root(
            BasicPathNode {
                mpt,
                trie_node: root_trie_node,
                path_start_steps: 0,
                full_path_to_node: Default::default(),
                path_db_key: Default::default(),
                next_child_index: 0,
            },
            mpt_is_empty,
        ))
    }

    fn load_into(
        parent_node: &Self, mpt: &mut Option<Mpt>, node_child_index: u8,
        supposed_merkle_root: &MerkleHash,
    ) -> Result<Self>
    {
        let parent_path = &parent_node.get_basic_path_node().full_path_to_node;

        let path_db_key =
            CompressedPathRaw::extend_path(parent_path, node_child_index);

        let trie_node = parent_node
            .load_node_wrapper(mpt.as_mut().unwrap(), &path_db_key)?;

        assert_eq!(
            trie_node.get_merkle(),
            supposed_merkle_root,
            "loaded trie node merkle hash {:?} != supposed merkle hash {:?}, path_db_key={:?}",
            trie_node.get_merkle(),
            supposed_merkle_root,
            path_db_key,
        );

        let full_path_to_node = CompressedPathRaw::join_connected_paths(
            parent_path,
            node_child_index,
            &trie_node.compressed_path_ref(),
        );

        Ok(Self::new_loaded(
            BasicPathNode {
                mpt: mpt.take(),
                trie_node,
                path_start_steps: path_db_key.path_steps(),
                full_path_to_node,
                path_db_key,
                next_child_index: 0,
            },
            parent_node,
        ))
    }

    fn open_child_index(&mut self, child_index: u8) -> Result<Option<Self>>;
}

// TODO: What's the value of RwPathNodeTrait? It seems sufficient now to have
// only ReadWritePathNode. We may have a chance to move out subtree_size related
// fields from ReadWritePathNode and create a new SnapshotMptRWPathNode to for
// maintenance of subtree size.
pub trait RwPathNodeTrait<Mpt: GetRwMpt>: PathNodeTrait<Mpt> {
    fn new(
        basic_node: BasicPathNode<Mpt>, parent_node: &Self, value_size: usize,
    ) -> Self {
        let mut this_node = Self::new_loaded(basic_node, parent_node);
        this_node.get_read_write_path_node().is_loaded = false;

        if value_size > 0 {
            let key_size = this_node
                .get_basic_path_node()
                .full_path_to_node
                .path_size();
            let new_key_value_rlp_size =
                rlp_key_value_len(key_size, value_size);
            this_node.get_read_write_path_node().subtree_size_delta =
                new_key_value_rlp_size as i64;
            this_node.get_read_write_path_node().delta_subtree_size =
                new_key_value_rlp_size;
        }

        this_node
    }

    fn get_read_write_path_node(&mut self) -> &mut ReadWritePathNode<Mpt>;

    fn get_read_only_path_node(&self) -> &ReadWritePathNode<Mpt>;

    fn unmatched_child_node_for_path_diversion(
        self, new_path_db_key: CompressedPathRaw,
        new_compressed_path: CompressedPathRaw,
    ) -> Result<ReadWritePathNode<Mpt>>;

    fn replace_value_valid(&mut self, value: Box<[u8]>);

    fn delete_value_assumed_existence(&mut self);
}

impl<Mpt: GetReadMpt> PathNodeTrait<Mpt> for BasicPathNode<Mpt> {
    fn new_loaded(basic_node: BasicPathNode<Mpt>, _parent_node: &Self) -> Self {
        basic_node
    }

    fn get_basic_path_node(&self) -> &BasicPathNode<Mpt> { self }

    fn get_basic_path_node_mut(&mut self) -> &mut BasicPathNode<Mpt> { self }

    fn open_child_index(&mut self, child_index: u8) -> Result<Option<Self>> {
        self.next_child_index = child_index;

        match self
            .trie_node
            .get_children_table_ref()
            .get_child(child_index)
        {
            None => Ok(None),

            Some(&SubtreeMerkleWithSize {
                merkle: ref supposed_merkle_hash,
                ..
            }) => {
                let mut mpt_taken = self.mpt.take();
                Ok(Some(Self::load_into(
                    self,
                    &mut mpt_taken,
                    child_index,
                    supposed_merkle_hash,
                )?))
            }
        }
    }
}

impl<Mpt: GetRwMpt> PathNodeTrait<Mpt> for ReadWritePathNode<Mpt> {
    fn new_loaded(basic_node: BasicPathNode<Mpt>, parent_node: &Self) -> Self {
        Self {
            basic_node,
            is_loaded: true,
            maybe_first_realized_child_index: Self::NULL_CHILD_INDEX,
            the_first_child_if_pending: None,
            maybe_compressed_path_split_child_index: Self::NULL_CHILD_INDEX,
            maybe_compressed_path_split_child_node: None,
            subtree_size_delta: 0,
            delta_subtree_size: 0,
            has_io_error: parent_node.has_io_error,
            db_committed: false,
        }
    }

    fn get_basic_path_node(&self) -> &BasicPathNode<Mpt> { &self.basic_node }

    fn get_basic_path_node_mut(&mut self) -> &mut BasicPathNode<Mpt> {
        &mut self.basic_node
    }

    fn commit(mut self, parent: &mut Self) -> Result<Option<Mpt>> {
        self.skip_till_child_index(CHILDREN_COUNT as u8)?;
        if !self.is_node_empty() {
            let mut maybe_pending_child =
                self.the_first_child_if_pending.take();
            if let Some(pending_child) = maybe_pending_child.as_mut() {
                // Handle path compression. Move the VanillaTrieNode from child
                // into self with appropriate modifications.
                if !self.trie_node.has_value()
                    && self.trie_node.get_children_count() == 1
                {
                    // Since the current trie node is empty, we
                    // update the child_node and replace current trie_node
                    // with it.
                    //
                    // The subtree size isn't affected.
                    let child_trie_node = &mut pending_child.trie_node;
                    let new_path = CompressedPathRaw::join_connected_paths(
                        &self.trie_node.compressed_path_ref(),
                        self.maybe_first_realized_child_index,
                        &child_trie_node.compressed_path_ref(),
                    );

                    child_trie_node.set_compressed_path(new_path);

                    mem::replace(
                        &mut self.trie_node,
                        mem::replace(child_trie_node, Default::default()),
                    );
                }
                // Write out the child, reset to empty in case of path
                // compression, or write out without change.
                Self::write_out_pending_child(
                    &mut self.mpt,
                    &mut maybe_pending_child,
                )?;
            }
            self.compute_merkle();
        }

        parent.set_concluded_child(self)
    }

    fn commit_root(
        mut self, mpt_taken: &mut Option<Mpt>,
    ) -> Result<MerkleHash> {
        self.skip_till_child_index(CHILDREN_COUNT as u8)?;
        if self.is_node_empty() {
            *mpt_taken = self.write_out()?;
            Ok(MERKLE_NULL_NODE)
        } else {
            Self::write_out_pending_child(
                &mut self.basic_node.mpt,
                &mut self.the_first_child_if_pending,
            )?;
            let merkle = self.compute_merkle();
            *mpt_taken = self.write_out()?;
            Ok(merkle)
        }
    }

    fn open_child_index(&mut self, child_index: u8) -> Result<Option<Self>> {
        self.skip_till_child_index(child_index)?;

        match Self::open_maybe_split_compressed_path_node(
            self.maybe_compressed_path_split_child_index,
            &mut self.maybe_compressed_path_split_child_node,
            child_index,
        )? {
            Some(mut node) => {
                self.next_child_index = child_index;
                node.mpt = self.take_mpt();

                Ok(Some(*node))
            }
            None => match self.basic_node.open_child_index(child_index) {
                Err(e) => Err(e),
                Ok(None) => Ok(None),
                Ok(Some(new_basic_node)) => {
                    Ok(Some(Self::new_loaded(new_basic_node, self)))
                }
            },
        }
    }
}

impl<Mpt: GetRwMpt> RwPathNodeTrait<Mpt> for ReadWritePathNode<Mpt> {
    fn get_read_write_path_node(&mut self) -> &mut ReadWritePathNode<Mpt> {
        self
    }

    fn get_read_only_path_node(&self) -> &ReadWritePathNode<Mpt> { self }

    /// When a node's compressed path is split under PathDiverted insertion, we
    /// must "remove" the original node, create a new node for the
    /// unmatched_path and children_table.
    fn unmatched_child_node_for_path_diversion(
        mut self, new_path_db_key: CompressedPathRaw,
        new_compressed_path: CompressedPathRaw,
    ) -> Result<Self>
    {
        let mut child_node;
        if self.is_loaded {
            child_node = Self {
                basic_node: BasicPathNode {
                    mpt: None,
                    trie_node: Default::default(),
                    path_start_steps: new_path_db_key.path_steps(),
                    full_path_to_node: self.full_path_to_node.clone(),
                    path_db_key: new_path_db_key,
                    next_child_index: self.next_child_index,
                },
                is_loaded: false,
                maybe_first_realized_child_index: self
                    .maybe_first_realized_child_index,
                the_first_child_if_pending: self
                    .the_first_child_if_pending
                    .take(),
                maybe_compressed_path_split_child_index: self
                    .maybe_compressed_path_split_child_index,
                maybe_compressed_path_split_child_node: self
                    .maybe_compressed_path_split_child_node
                    .take(),
                subtree_size_delta: self.subtree_size_delta,
                delta_subtree_size: self.delta_subtree_size,
                has_io_error: self.has_io_error,
                db_committed: self.db_committed,
            };

            mem::swap(&mut child_node.trie_node, &mut self.trie_node);
            child_node.mpt = self.write_out()?;
        } else {
            self.get_basic_path_node_mut().path_start_steps =
                new_path_db_key.path_steps();
            self.get_basic_path_node_mut().path_db_key = new_path_db_key;
            child_node = self;
        };

        child_node
            .trie_node
            .set_compressed_path(new_compressed_path);

        Ok(child_node)
    }

    fn replace_value_valid(&mut self, value: Box<[u8]>) {
        let key_len = self.full_path_to_node.path_size();
        let mut size_delta = rlp_key_value_len(key_len, value.len()) as i64;
        let maybe_old_value = self.trie_node.replace_value_valid(value);
        match maybe_old_value {
            MptValue::None => {
                // No-op
            }
            MptValue::TombStone => {
                // There is no TombStone in Snapshot MPT.
                unreachable!()
            }
            MptValue::Some(old_value) => {
                size_delta -= rlp_key_value_len(key_len, old_value.len()) as i64
            }
        }

        self.subtree_size_delta += size_delta;
    }

    fn delete_value_assumed_existence(&mut self) {
        let old_value = unsafe { self.trie_node.delete_value_unchecked() };
        let key_size = self.full_path_to_node.path_size();
        self.subtree_size_delta -=
            rlp_key_value_len(key_size, old_value.len()) as i64;
        // The "delta" for marked deletion is considered (key, "").
        self.delta_subtree_size += rlp_key_value_len(key_size, 0);
    }
}

impl<Mpt> ReadWritePathNode<Mpt> {
    /// Initial value for `self.first_realized_child_index`, meaning these is no
    /// child concluded in cursor iteration.
    const NULL_CHILD_INDEX: u8 = 16;

    pub fn disable_path_compression(&mut self) {
        self.maybe_first_realized_child_index = 0;
    }

    fn get_has_io_error(&self) -> bool { self.io_error().get() }

    fn is_node_empty(&self) -> bool {
        !self.trie_node.has_value() && self.trie_node.get_children_count() == 0
    }

    fn compute_merkle(&mut self) -> MerkleHash {
        let path_merkle = self
            .trie_node
            .compute_merkle(self.trie_node.get_children_merkles().as_ref());
        self.trie_node.set_merkle(&path_merkle);

        path_merkle
    }
}

impl<Mpt: GetRwMpt> ReadWritePathNode<Mpt> {
    fn write_out(mut self) -> Result<Option<Mpt>> {
        // There is nothing to worry about for path_db_key changes in case of
        // path compression changes, because db changes is as simple as
        // data overwriting / deletion / creation.
        if self.is_node_empty() {
            // In-place mode.
            let io_mpts = self.basic_node.mpt.as_mut_assumed_owner();
            if io_mpts.is_in_place_update() && self.is_loaded {
                let result = io_mpts
                    .get_write_mpt()
                    .delete_node(&self.basic_node.path_db_key);
                if result.is_err() {
                    self.set_has_io_error();
                    bail!(result.unwrap_err());
                }
            }
        } else {
            let result = self
                .basic_node
                .mpt
                .as_mut_assumed_owner()
                .get_write_mpt()
                .write_node(
                    &self.basic_node.path_db_key,
                    &self.basic_node.trie_node,
                );
            if result.is_err() {
                self.set_has_io_error();
                bail!(result.unwrap_err());
            }
        }

        self.db_committed = true;
        Ok(self.take_mpt())
    }

    /// We have to pass struct fields because of borrow checker.
    fn open_maybe_split_compressed_path_node(
        maybe_compressed_path_split_child_index: u8,
        maybe_compressed_path_split_child_node: &mut Option<Box<Self>>,
        child_index: u8,
    ) -> Result<Option<Box<Self>>>
    {
        if child_index == maybe_compressed_path_split_child_index {
            Ok(maybe_compressed_path_split_child_node.take())
        } else {
            Ok(None)
        }
    }

    fn skip_till_child_index(&mut self, child_index: u8) -> Result<()> {
        let is_save_as_mode =
            self.mpt.as_ref_assumed_owner().is_save_as_write();
        for (
            this_child_index,
            &SubtreeMerkleWithSize {
                merkle: ref this_child_node_merkle_ref,
                ..
            },
        ) in self
            .basic_node
            .trie_node
            .get_children_table_ref()
            .iter()
            .set_start_index(self.next_child_index)
        {
            if this_child_index < child_index {
                let mut child_node;
                // Handle compressed path logics for concluded subtrees.
                // The value of the root node is guaranteed to be settled before
                // changes in the subtree.
                if !self.trie_node.has_value()
                    && self.maybe_first_realized_child_index
                        == Self::NULL_CHILD_INDEX
                {
                    // Even though this child isn't modified, path
                    // compression may happen if all
                    // later children are deleted.
                    self.maybe_first_realized_child_index = this_child_index;
                    let mut mpt_taken = self.basic_node.mpt.take();
                    child_node =
                        match Self::open_maybe_split_compressed_path_node(
                            self.maybe_compressed_path_split_child_index,
                            &mut self.maybe_compressed_path_split_child_node,
                            this_child_index,
                        )? {
                            Some(mut child_node) => {
                                child_node.mpt = mpt_taken;
                                child_node.compute_merkle();

                                child_node
                            }
                            None => Box::new(ReadWritePathNode::load_into(
                                self,
                                &mut mpt_taken,
                                this_child_index,
                                this_child_node_merkle_ref,
                            )?),
                        };
                    // Save-as mode.
                    if is_save_as_mode {
                        MptCursorRw::<Mpt, Self>::copy_subtree_without_root(
                            &mut child_node,
                        )?;
                    }
                } else {
                    //  Path compression is unnecessary.
                    Self::write_out_pending_child(
                        &mut self.basic_node.mpt,
                        &mut self.the_first_child_if_pending,
                    )?;
                    child_node =
                        match Self::open_maybe_split_compressed_path_node(
                            self.maybe_compressed_path_split_child_index,
                            &mut self.maybe_compressed_path_split_child_node,
                            this_child_index,
                        )? {
                            Some(mut child_node) => {
                                child_node.mpt = self.basic_node.mpt.take();
                                child_node.compute_merkle();

                                child_node
                            }
                            None => {
                                if is_save_as_mode {
                                    let mut mpt_taken =
                                        self.basic_node.mpt.take();
                                    let mut child_node =
                                        ReadWritePathNode::load_into(
                                            self,
                                            &mut mpt_taken,
                                            this_child_index,
                                            this_child_node_merkle_ref,
                                        )?;

                                    MptCursorRw::<Mpt, Self>::copy_subtree_without_root(
                                        &mut child_node,
                                    )?;

                                    Box::new(child_node)
                                } else {
                                    continue;
                                }
                            }
                        };
                }
                unsafe {
                    let mut_self = &mut *(self as *const Self as *mut Self);
                    mut_self.next_child_index = this_child_index;
                    let mpt_taken =
                        mut_self.set_concluded_child(*child_node)?;
                    self.basic_node.mpt = mpt_taken;
                }
            } else {
                break;
            }
        }
        // We don't set next_child_index here in this method because there is
        // always follow-ups actions which set next_child_index, or
        // next_child_index no longer matter.
        Ok(())
    }

    fn set_concluded_child(
        &mut self, mut child_node: ReadWritePathNode<Mpt>,
    ) -> Result<Option<Mpt>> {
        self.subtree_size_delta += child_node.subtree_size_delta;
        self.delta_subtree_size += child_node.delta_subtree_size;

        if !child_node.is_node_empty() {
            let subtree_size = (self
                .basic_node
                .trie_node
                .get_child(self.basic_node.next_child_index)
                // Unwrap is safe. See comment below.
                .unwrap()
                .subtree_size as i64
                + child_node.subtree_size_delta)
                as u64;

            // The safety is guaranteed because when the child doesn't
            // originally exist, the child was added to the children table when
            // the child was created.
            unsafe {
                self.basic_node.trie_node.replace_child_unchecked(
                    self.basic_node.next_child_index,
                    SubtreeMerkleWithSize {
                        merkle: child_node.trie_node.get_merkle().clone(),
                        subtree_size,
                        delta_subtree_size: child_node.delta_subtree_size,
                    },
                )
            };

            // The node won't merge with its first children, because either the
            // node has value, or the child node is the second child. The
            // assumption here is that in db and rust string comparison a string
            // that is a prefix of another string is considered smaller.
            if self.trie_node.has_value() {
                Ok(child_node.write_out()?)
            } else if self.maybe_first_realized_child_index
                != Self::NULL_CHILD_INDEX
            {
                Self::write_out_pending_child(
                    &mut child_node.mpt,
                    &mut self.the_first_child_if_pending,
                )?;
                Ok(child_node.write_out()?)
            } else {
                // This child is the first realized child.
                self.maybe_first_realized_child_index = self.next_child_index;
                let mpt_taken = child_node.take_mpt();
                self.the_first_child_if_pending = Some(Box::new(child_node));
                Ok(mpt_taken)
            }
        } else {
            let mpt_taken = child_node.write_out()?;

            // The safety is guaranteed by condition.
            unsafe {
                self.basic_node
                    .trie_node
                    .delete_child_unchecked(self.basic_node.next_child_index)
            };

            Ok(mpt_taken)
        }
    }

    /// This function is written like this because we want rust borrow checker
    /// to work smart.
    fn write_out_pending_child(
        mpt: &mut Option<Mpt>,
        the_first_child: &mut Option<Box<ReadWritePathNode<Mpt>>>,
    ) -> Result<()>
    {
        if the_first_child.is_some() {
            let mut child = the_first_child.take().unwrap();
            child.mpt = mpt.take();
            *mpt = child.write_out()?;
        }
        Ok(())
    }
}

impl<Mpt> Drop for BasicPathNode<Mpt> {
    fn drop(&mut self) {
        // No-op for read only access.
    }
}

impl<Mpt> Drop for ReadWritePathNode<Mpt> {
    fn drop(&mut self) {
        if !self.get_has_io_error() {
            if self.db_committed == false {
                self.set_has_io_error();
                assert_eq!(
                    true,
                    self.db_committed,
                    "Node {:?}, {:?} uncommitted in MptCursorRw.",
                    self.path_db_key.as_ref(),
                    self.trie_node.get_merkle(),
                );
            }
        }
    }
}

pub trait GetReadMpt {
    fn get_merkle_root(&self) -> MerkleHash;

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitRead;
}

pub trait GetRwMpt: GetReadMpt {
    fn get_write_mpt(&mut self) -> &mut dyn SnapshotMptTraitRw;

    fn get_write_and_read_mpt(
        &mut self,
    ) -> (
        &mut dyn SnapshotMptTraitRw,
        Option<&mut dyn SnapshotMptTraitReadAndIterate>,
    );

    fn is_save_as_write(&self) -> bool;
    fn is_in_place_update(&self) -> bool;
}

impl GetReadMpt for &mut dyn SnapshotMptTraitRead {
    fn get_merkle_root(&self) -> MerkleHash {
        SnapshotMptTraitRead::get_merkle_root(*self)
    }

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitRead { *self }
}

pub trait TakeMpt<Mpt> {
    fn take_mpt(&mut self) -> Option<Mpt>;
}

impl<Mpt> TakeMpt<Mpt> for BasicPathNode<Mpt> {
    fn take_mpt(&mut self) -> Option<Mpt> { self.mpt.take() }
}

impl<Mpt> TakeMpt<Mpt> for ReadWritePathNode<Mpt> {
    fn take_mpt(&mut self) -> Option<Mpt> { self.basic_node.take_mpt() }
}

impl<Mpt, PathNode> TakeMpt<Mpt> for MptCursor<Mpt, PathNode> {
    fn take_mpt(&mut self) -> Option<Mpt> { self.mpt.take() }
}

impl<Mpt, PathNode> TakeMpt<Mpt> for MptCursorRw<Mpt, PathNode> {
    fn take_mpt(&mut self) -> Option<Mpt> { self.mpt.take() }
}

pub trait CursorSetIoError {
    fn io_error(&self) -> &Cell<bool>;
    fn set_has_io_error(&self);
}

impl<Mpt, PathNode> CursorSetIoError for MptCursorRw<Mpt, PathNode> {
    fn io_error(&self) -> &Cell<bool> { &self.io_error }

    fn set_has_io_error(&self) { self.io_error.replace(true); }
}

impl CursorSetIoError for *const Cell<bool> {
    fn io_error(&self) -> &Cell<bool> { unsafe { &**self } }

    fn set_has_io_error(&self) { self.io_error().replace(true); }
}

impl<Mpt> CursorSetIoError for ReadWritePathNode<Mpt> {
    fn io_error(&self) -> &Cell<bool> { unsafe { &*self.has_io_error } }

    fn set_has_io_error(&self) { self.io_error().replace(true); }
}

struct MptCursorGetChild {}

static MPT_CURSOR_GET_CHILD: MptCursorGetChild = MptCursorGetChild {};

impl<'node> GetChildTrait<'node> for MptCursorGetChild {
    type ChildIdType = ();

    fn get_child(&'node self, _child_index: u8) -> Option<()> { None }
}

pub enum CursorPopNodesTerminal<'key> {
    Arrived,
    Descent {
        key_remaining: &'key [u8],
        child_index: u8,
    },
    PathDiverted(WalkStop<'key, ()>),
}

pub enum CursorOpenPathTerminal<'key> {
    Arrived,
    ChildNotFound {
        key_remaining: &'key [u8],
        child_index: u8,
    },
    PathDiverted(WalkStop<'key, ()>),
}

pub trait OptionUnwrapBorrowAssumedSomeExtension<T> {
    fn as_ref_assumed_owner(&self) -> &T;
    fn as_mut_assumed_owner(&mut self) -> &mut T;
}

impl<Mpt> OptionUnwrapBorrowAssumedSomeExtension<Mpt> for Option<Mpt> {
    fn as_ref_assumed_owner(&self) -> &Mpt { self.as_ref().unwrap() }

    fn as_mut_assumed_owner(&mut self) -> &mut Mpt { self.as_mut().unwrap() }
}

pub fn rlp_str_len(len: usize) -> u64 {
    if len <= 55 {
        len as u64 + 1
    } else {
        let mut len_of_len = 0i32;
        while (len >> (8 * len_of_len)) > 0 {
            len_of_len += 1;
        }

        len as u64 + 1 + len_of_len as u64
    }
}

/// We assume that the keys and values are serialized in separate vector,
/// therefore we only add up those rlp string lenghts.
/// The rlp bytes for the up-most structures are ignored for sync slicer.
pub fn rlp_key_value_len(key_len: u16, value_len: usize) -> u64 {
    rlp_str_len(key_len.into()) + rlp_str_len(value_len)
}

use super::{
    super::{super::storage_db::snapshot_mpt::*, errors::*},
    children_table::*,
    compressed_path::CompressedPathTrait,
    mpt_value::MptValue,
    trie_node::{TrieNodeTrait, VanillaTrieNode},
    trie_proof::*,
    walk::*,
    CompressedPathRaw,
};
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use std::{
    cell::Cell,
    hint::unreachable_unchecked,
    mem,
    ops::{Deref, DerefMut},
    vec::Vec,
};
