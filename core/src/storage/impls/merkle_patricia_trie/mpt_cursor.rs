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
            trie_nodes.push(TrieProofNode(
                node.get_basic_path_node().trie_node.0.clone(),
            ))
        }
        TrieProof::new(trie_nodes)
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
        self.path_nodes.pop().unwrap().commit_root()
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
                            &last_node
                                .get_basic_path_node()
                                .full_path_to_node
                                .path_slice()
                                [aligned_path_start_offset as usize..],
                            matched_path.end_mask(),
                        );
                        let original_compressed_path_ref =
                            last_trie_node.compressed_path_ref();
                        let actual_unmatched_path_remaining =
                            CompressedPathRaw::new(
                                &unmatched_path_remaining.path_slice()[0
                                    ..(original_compressed_path_ref.path_size()
                                        - actual_matched_path.path_size())
                                        as usize],
                                original_compressed_path_ref.end_mask(),
                            );

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
                            // process the expand of compressed path.
                        }
                    }
                    return Ok(CursorOpenPathTerminal::PathDiverted(next_step));
                }
            }
        }
    }
}

pub struct MptCursorRw<Mpt> {
    cursor: MptCursor<Mpt, ReadWritePathNode<Mpt>>,

    io_error: Cell<bool>,
}

impl<Mpt> Deref for MptCursorRw<Mpt> {
    type Target = MptCursor<Mpt, ReadWritePathNode<Mpt>>;

    fn deref(&self) -> &Self::Target { &self.cursor }
}

impl<Mpt> DerefMut for MptCursorRw<Mpt> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.cursor }
}

impl<Mpt: GetRwMpt> MptCursorRw<Mpt> {
    pub fn new(mpt: Mpt) -> Self {
        Self {
            cursor: MptCursor::new(mpt),
            io_error: Cell::new(false),
        }
    }

    pub fn load_root(&mut self) -> Result<()> {
        let root_node = ReadWritePathNode::load_root(self)?;
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
                // FIXME: new method for ReadWritePathNode.
                let new_node = ReadWritePathNode::new(
                    BasicPathNode::new(
                        SnapshotMptNode(
                            VanillaTrieNode::new(
                                MERKLE_NULL_NODE,
                                Default::default(),
                                Some(value),
                                key_remaining.into(),
                            ),
                            0,
                        ),
                        parent_node.take_mpt(),
                        &parent_node.full_path_to_node,
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
                // Split compressed path and update the trie nodes.
                // The path diversion always happens on the right side:
                // the new path is larger than
                // the original path. So we
                // update and close the old node, then create
                // a new node.
                let mut last_node = self.path_nodes.pop().unwrap();
                let parent_node = self.path_nodes.last_mut().unwrap();

                last_node
                    .trie_node
                    .set_compressed_path(unmatched_path_remaining);

                let mut fork_node = ReadWritePathNode::new_loaded(
                    BasicPathNode::new(
                        SnapshotMptNode(
                            VanillaTrieNode::new(
                                MERKLE_NULL_NODE,
                                VanillaChildrenTable::new_from_one_child(
                                    unmatched_child_index,
                                    &MERKLE_NULL_NODE,
                                ),
                                None,
                                matched_path,
                            ),
                            0,
                        ),
                        parent_node.take_mpt(),
                        &parent_node.full_path_to_node,
                        parent_node.next_child_index,
                    ),
                    parent_node,
                );
                // FIXME: the new node has the first child point to
                // unmatched_child_node. Move into BasicPathNode.
                fork_node.next_child_index = unmatched_child_index;

                last_node.path_db_key = CompressedPathRaw::concat(
                    &fork_node.full_path_to_node,
                    unmatched_child_index,
                    &CompressedPathRaw::default(),
                );
                match key_child_index {
                    Some(child_index) => unsafe {
                        // Actually safe because the key_child_index is
                        // valid.
                        fork_node.first_realized_child_index =
                            unmatched_child_index;
                        last_node.commit(&mut fork_node)?;

                        // Move on to the next child: diverted path.
                        fork_node.next_child_index = child_index;

                        fork_node.trie_node.add_new_child_unchecked(
                            child_index,
                            &MERKLE_NULL_NODE,
                        );

                        let value_len = value.len();
                        let value_node = ReadWritePathNode::new(
                            BasicPathNode::new(
                                SnapshotMptNode(
                                    VanillaTrieNode::new(
                                        MERKLE_NULL_NODE,
                                        Default::default(),
                                        Some(value),
                                        key_remaining.into(),
                                    ),
                                    0,
                                ),
                                fork_node.take_mpt(),
                                &fork_node.full_path_to_node,
                                child_index,
                            ),
                            &fork_node,
                            value_len,
                        );

                        self.path_nodes.push(fork_node);
                        self.path_nodes.push(value_node);
                    },
                    None => {
                        fork_node.trie_node.replace_value_valid(value);
                        last_node.commit(&mut fork_node)?;

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
                if last_node.trie_node.has_value() {
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
            // FIXME: path, SnapshotMptNode.
            if let Some((path, trie_node, subtree_size)) = match iter.next() {
                Err(e) => {
                    subtree_root.has_io_error.set_has_io_error();
                    bail!(e);
                }
                Ok(item) => item,
            } {
                let result = dest_mpt.write_node(
                    &path,
                    &SnapshotMptNode(trie_node, subtree_size),
                );
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

impl<Mpt: GetReadMpt, T: CursorSetIoError + TakeMpt<Mpt>>
    CursorLoadNodeWrapper<Mpt> for T
{
    fn load_node_wrapper(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode> {
        let result = mpt.get_read_mpt().load_node(path);
        if result.is_err() {
            self.set_has_io_error();
        }
        result?.ok_or(Error::from(ErrorKind::SnapshotMPTTrieNodeNotFound))
    }
}

pub trait CursorToRootNode<Mpt: GetReadMpt, PathNode: PathNodeTrait<Mpt>> {
    fn new_root(&self, basic_node: BasicPathNode<Mpt>) -> PathNode;
}

impl<Mpt: GetReadMpt, Cursor: CursorLoadNodeWrapper<Mpt>>
    CursorToRootNode<Mpt, BasicPathNode<Mpt>> for Cursor
{
    fn new_root(&self, basic_node: BasicPathNode<Mpt>) -> BasicPathNode<Mpt> {
        basic_node
    }
}

impl<Mpt: GetRwMpt> CursorToRootNode<Mpt, ReadWritePathNode<Mpt>>
    for MptCursorRw<Mpt>
{
    fn new_root(
        &self, basic_node: BasicPathNode<Mpt>,
    ) -> ReadWritePathNode<Mpt> {
        ReadWritePathNode {
            basic_node,

            first_realized_child_index: 0,
            the_first_child: None,
            subtree_size_delta: 0,
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
        let full_path_to_node = CompressedPathRaw::concat(
            parent_path,
            child_index,
            &trie_node.compressed_path_ref(),
        );

        Self {
            mpt,
            trie_node,
            path_start_steps: parent_path.path_steps() + 1,
            full_path_to_node,
            path_db_key: CompressedPathRaw::concat(
                parent_path,
                child_index,
                &CompressedPathRaw::default(),
            ),
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

    first_realized_child_index: u8,
    the_first_child: Option<Box<ReadWritePathNode<Mpt>>>,

    subtree_size_delta: i64,

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
    fn commit_root(self) -> Result<MerkleHash> {
        Ok(self.get_basic_path_node().trie_node.0.get_merkle().clone())
    }

    fn get_basic_path_node(&self) -> &BasicPathNode<Mpt>;

    fn get_basic_path_node_mut(&mut self) -> &mut BasicPathNode<Mpt>;

    fn load_root<
        Cursor: CursorLoadNodeWrapper<Mpt> + CursorToRootNode<Mpt, Self>,
    >(
        cursor: &mut Cursor,
    ) -> Result<Self> {
        let mut mpt = cursor.take_mpt();
        let root_trie_node = cursor.load_node_wrapper(
            mpt.as_mut_assumed_owner(),
            &CompressedPathRaw::default(),
        )?;

        let supposed_merkle_root = mpt.as_ref_assumed_owner().get_merkle_root();
        assert_eq!(
            root_trie_node.get_merkle(),
            supposed_merkle_root,
            "loaded root trie node merkle hash {:?} != supposed merkle hash {:?}",
            root_trie_node.get_merkle(),
            supposed_merkle_root,
        );

        Ok(cursor.new_root(BasicPathNode {
            mpt,
            trie_node: root_trie_node,
            path_start_steps: 0,
            full_path_to_node: Default::default(),
            path_db_key: Default::default(),
            next_child_index: 0,
        }))
    }

    fn load_into(
        parent_node: &Self, mut mpt: Option<Mpt>, node_child_index: u8,
        supposed_merkle_root: &MerkleHash,
    ) -> Result<Self>
    {
        let parent_path = &parent_node.get_basic_path_node().full_path_to_node;

        let path_db_key = CompressedPathRaw::concat(
            parent_path,
            node_child_index,
            &CompressedPathRaw::default(),
        );

        let trie_node = parent_node
            .load_node_wrapper(mpt.as_mut().unwrap(), &path_db_key)?;
        assert_eq!(
            trie_node.get_merkle(),
            supposed_merkle_root,
            "loaded trie node merkle hash {:?} != supposed merkle hash {:?}",
            trie_node.get_merkle(),
            supposed_merkle_root,
        );

        let full_path_to_node = CompressedPathRaw::concat(
            parent_path,
            node_child_index,
            &trie_node.compressed_path_ref(),
        );

        Ok(Self::new_loaded(
            BasicPathNode {
                mpt,
                trie_node,
                path_start_steps: parent_path.path_steps() + 1,
                full_path_to_node,
                path_db_key,
                next_child_index: 0,
            },
            parent_node,
        ))
    }

    fn open_child_index(&mut self, child_index: u8) -> Result<Option<Self>>;
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
            Some(supposed_merkle_hash) => {
                let mpt = self.mpt.take();
                Ok(Some(Self::load_into(
                    self,
                    mpt,
                    child_index,
                    &supposed_merkle_hash,
                )?))
            }
        }
    }
}

impl<Mpt: GetRwMpt> PathNodeTrait<Mpt> for ReadWritePathNode<Mpt> {
    fn new_loaded(basic_node: BasicPathNode<Mpt>, parent_node: &Self) -> Self {
        Self {
            basic_node,
            first_realized_child_index: 0,
            the_first_child: None,
            subtree_size_delta: 0,
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
            match self.the_first_child.take() {
                Some(child) => {
                    // Handle path compression.
                    if !self.trie_node.has_value()
                        && self.trie_node.get_children_count() == 1
                    {
                        // Since the current trie node is empty, we
                        // update the child_node and replace current trie_node
                        // with it.
                        //
                        // The subtree size isn't affected.
                        let mut child_node = child;
                        let child_trie_node = &mut child_node.trie_node;
                        let new_path = CompressedPathRaw::concat(
                            &self.trie_node.compressed_path_ref(),
                            self.first_realized_child_index,
                            &child_trie_node.compressed_path_ref(),
                        );

                        child_trie_node.set_compressed_path(new_path);

                        mem::replace(
                            &mut self.trie_node,
                            mem::replace(child_trie_node, Default::default()),
                        );

                        child_node.write_out()?;
                    }
                }
                None => {}
            }
            self.compute_merkle();
        }

        parent.set_concluded_child(self)
    }

    fn commit_root(mut self) -> Result<MerkleHash> {
        self.skip_till_child_index(CHILDREN_COUNT as u8)?;
        if !self.is_node_empty() {
            // modification
            Self::write_out_pending_child(
                &mut self.basic_node.mpt,
                &mut self.the_first_child,
            )?;
        }

        let merkle = self.compute_merkle();
        self.write_out()?;
        Ok(merkle)
    }

    fn open_child_index(&mut self, child_index: u8) -> Result<Option<Self>> {
        self.skip_till_child_index(child_index)?;

        match self.basic_node.open_child_index(child_index) {
            Err(e) => Err(e),
            Ok(None) => Ok(None),
            Ok(Some(new_basic_node)) => {
                Ok(Some(Self::new_loaded(new_basic_node, self)))
            }
        }
    }
}

impl<Mpt> ReadWritePathNode<Mpt> {
    fn replace_value_valid(&mut self, value: Box<[u8]>) {
        let key_len = self.full_path_to_node.path_size();
        let mut size_delta: i64 = rlp_key_value_len(key_len, value.len());
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
                size_delta += rlp_key_value_len(key_len, old_value.len())
            }
        }

        self.subtree_size_delta += size_delta;
    }

    fn delete_value_assumed_existence(&mut self) {
        let old_value = unsafe { self.trie_node.delete_value_unchecked() };
        self.subtree_size_delta -= rlp_key_value_len(
            self.full_path_to_node.path_size(),
            old_value.len(),
        );
    }

    fn get_has_io_error(&self) -> bool { self.io_error().get() }

    fn is_node_empty(&self) -> bool {
        !self.trie_node.has_value() && self.first_realized_child_index == 0
    }

    fn compute_merkle(&mut self) -> MerkleHash {
        let path_merkle = self
            .trie_node
            .compute_merkle(self.trie_node.get_children_merkle());
        self.trie_node.set_merkle(&path_merkle);

        path_merkle
    }
}

impl<Mpt: GetRwMpt> ReadWritePathNode<Mpt> {
    fn new(
        basic_node: BasicPathNode<Mpt>, parent_node: &Self, value_size: usize,
    ) -> Self {
        let mut this_node = Self::new_loaded(basic_node, parent_node);

        if value_size > 0 {
            this_node.subtree_size_delta = rlp_key_value_len(
                this_node.basic_node.full_path_to_node.path_size(),
                value_size,
            );
        }

        this_node
    }

    fn write_out(mut self) -> Result<Option<Mpt>> {
        // There is nothing to worry about for path_db_key changes in case of
        // path compression changes, because db changes is as simple as
        // data overwriting / deletion / creation.
        if self.is_node_empty() {
            // In-place mode.
            let io_mpts = self.basic_node.mpt.as_mut_assumed_owner();
            if io_mpts.is_in_place_update() {
                let result = io_mpts
                    .get_write_mpt()
                    .delete_node(&self.basic_node.path_db_key);
                if result.is_err() {
                    self.set_has_io_error();
                    bail!(result.unwrap_err());
                }
            }
        } else {
            self.trie_node.1 += self.subtree_size_delta;

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

    fn skip_till_child_index(&mut self, child_index: u8) -> Result<()> {
        for (this_child_index, this_child_node_merkle_ref) in self
            .basic_node
            .trie_node
            .get_children_table_ref()
            .iter()
            .set_start_index(self.next_child_index)
        {
            if this_child_index < child_index {
                // Handle compressed path logics.
                if !self.trie_node.has_value() {
                    if self.first_realized_child_index == 0 {
                        // Even though this child isn't modified, path
                        // compression may happen if all
                        // later children are deleted.
                        self.first_realized_child_index = this_child_index;
                        let npt = self.basic_node.mpt.take();
                        let mut child_node = ReadWritePathNode::load_into(
                            self,
                            npt,
                            this_child_index,
                            this_child_node_merkle_ref,
                        )?;
                        // Save-as mode.
                        if child_node
                            .mpt
                            .as_mut_assumed_owner()
                            .is_save_as_write()
                        {
                            MptCursorRw::copy_subtree_without_root(
                                &mut child_node,
                            )?;
                        }
                        self.the_first_child = Some(Box::new(child_node));
                    } else {
                        // There are more than one child. Path compression is
                        // unnecessary.
                        Self::write_out_pending_child(
                            &mut self.basic_node.mpt,
                            &mut self.the_first_child,
                        )?;
                        // Save-as mode.
                        if self
                            .basic_node
                            .mpt
                            .as_mut_assumed_owner()
                            .is_save_as_write()
                        {
                            let npt = self.basic_node.mpt.take();
                            let mut child_node = ReadWritePathNode::load_into(
                                self,
                                npt,
                                this_child_index,
                                this_child_node_merkle_ref,
                            )?;
                            MptCursorRw::copy_subtree_without_root(
                                &mut child_node,
                            )?;
                            child_node.write_out()?;
                        }
                    }
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

        if !child_node.is_node_empty() {
            // The safety is guaranteed by condition.
            unsafe {
                self.basic_node.trie_node.replace_child_unchecked(
                    self.basic_node.next_child_index,
                    child_node.trie_node.get_merkle(),
                )
            };

            // The node won't merge with its first children, because either the
            // node has value, or the child node is the second child. The
            // assumption here is that in db and rust string comparison a string
            // that is a prefix of another string is considered smaller.
            if self.trie_node.has_value() {
                Ok(child_node.write_out()?)
            } else if self.first_realized_child_index != 0 {
                Self::write_out_pending_child(
                    &mut self.basic_node.mpt,
                    &mut self.the_first_child,
                )?;
                Ok(child_node.write_out()?)
            } else {
                // This child is the first realized child.
                self.first_realized_child_index = self.next_child_index;
                let mpt_taken = child_node.take_mpt();
                self.the_first_child = Some(Box::new(child_node));
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

pub trait GetReadMpt {
    fn get_merkle_root(&self) -> &MerkleHash;

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitReadOnly;
}

pub trait GetRwMpt: GetReadMpt {
    fn get_write_mpt(&mut self) -> &mut dyn SnapshotMptTraitSingleWriter;

    fn get_write_and_read_mpt(
        &mut self,
    ) -> (
        &mut dyn SnapshotMptTraitSingleWriter,
        Option<&mut dyn SnapshotMptTraitReadOnly>,
    );

    fn is_save_as_write(&self) -> bool;
    fn is_in_place_update(&self) -> bool;
}

impl GetReadMpt for &mut dyn SnapshotMptTraitReadOnly {
    fn get_merkle_root(&self) -> &MerkleHash {
        SnapshotMptTraitReadOnly::get_merkle_root(*self)
    }

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitReadOnly { *self }
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

impl<Mpt> TakeMpt<Mpt> for MptCursorRw<Mpt> {
    fn take_mpt(&mut self) -> Option<Mpt> { self.mpt.take() }
}

pub trait CursorSetIoError {
    fn io_error(&self) -> &Cell<bool>;
    fn set_has_io_error(&self);
}

impl<Mpt> CursorSetIoError for MptCursorRw<Mpt> {
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

pub fn rlp_key_value_len(_key_len: u16, _value_len: usize) -> i64 {
    unimplemented!()
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
