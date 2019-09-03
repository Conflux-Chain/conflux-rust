// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Merge an MPT with sorted deletion and insertion stream.
/// The merge can be in-place or writing to a new MPT (save-as mode).
///
/// In the merging process, the merger keeps a path from root to a node. When
/// the next key to process from insertion or deletion stream lies outside the
/// subtree of the last node in the path, the last node is closed. New nodes are
/// open if the key goes further down extending the path. In in-place mode, node
/// deletions are executed and node writes happen when a modified node is
/// closed. In save-as mode, node deletion is no-op, and node writes happen
/// when a node is closed, and when opening the new node. All modified
/// node and skipped subtree are saved into the new MPT.
///
/// In a save-as copy, the base_mpt could be implemented as an iterator of the
/// original MPT because the original MPT is exactly visited in string order
/// by the path_db_key. (See definition of path_db_key below.)
// TODO(yz): In future merge can be made into multiple threads easily by merging
// different children in parallel then combine the root node.
pub struct MptMerger<'a> {
    mpts_in_request: Option<MptsInRequest<'a>>,
    path_nodes: Vec<NodeInMerge<'a>>,

    io_error: Cell<bool>,
}

#[allow(unused)]
struct MptsInRequest<'a> {
    maybe_readonly_mpt: Option<&'a mut dyn SnapshotMptTraitReadOnly>,
    out_mpt: &'a mut dyn SnapshotMptTraitSingleWriter,
}

trait SetIoError {
    fn set_has_io_error(&self);

    fn load_node_wrapper<'a>(
        &self, mpts_in_request: &mut MptsInRequest<'a>,
        path: &CompressedPathRaw,
    ) -> Result<VanillaTrieNode<MerkleHash>>
    {
        let result = if mpts_in_request.maybe_readonly_mpt.is_some() {
            mpts_in_request
                .maybe_readonly_mpt
                .as_mut()
                .unwrap()
                .load_node(path)
        } else {
            mpts_in_request.out_mpt.load_node(path)
        };
        if result.is_err() {
            self.set_has_io_error();
        }
        result?.ok_or(Error::from(ErrorKind::MPTMergeTrieNodeNotFound))
    }
}

trait OptionUnwrapBorrowAssumedSomeExtension<T> {
    fn io_mpts_readonly_assumed_owner(&self) -> &T;
    fn io_mpts_assumed_owner(&mut self) -> &mut T;
}

impl<'a> OptionUnwrapBorrowAssumedSomeExtension<MptsInRequest<'a>>
    for Option<MptsInRequest<'a>>
{
    fn io_mpts_readonly_assumed_owner(&self) -> &MptsInRequest<'a> {
        self.as_ref().unwrap()
    }

    fn io_mpts_assumed_owner(&mut self) -> &mut MptsInRequest<'a> {
        self.as_mut().unwrap()
    }
}

impl<'a> SetIoError for MptMerger<'a> {
    fn set_has_io_error(&self) { self.io_error.replace(true); }
}

impl<'a> MptMerger<'a> {
    fn copy_subtree_without_root(
        subtree_root: &mut NodeInMerge<'a>,
    ) -> Result<()> {
        let io_mpts = subtree_root.mpts_in_request.io_mpts_assumed_owner();
        let dest_mpt = &mut io_mpts.out_mpt;
        let source_mpt = io_mpts.maybe_readonly_mpt.as_mut().unwrap();
        let mut iter = match source_mpt.iterate_subtree_trie_nodes_without_root(
            &subtree_root.full_path_to_node,
        ) {
            Err(e) => {
                subtree_root.has_io_error.set_has_io_error();
                bail!(e);
            }
            Ok(iter) => iter,
        };
        loop {
            if let Some((path, trie_node, _subtree_size)) = match iter.next() {
                Err(e) => {
                    subtree_root.has_io_error.set_has_io_error();
                    bail!(e);
                }
                Ok(item) => item,
            } {
                let result = dest_mpt.write_node(&path, &trie_node);
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

impl CacheAlgoDataTrait for () {}

struct NodeInMerge<'a> {
    mpts_in_request: Option<MptsInRequest<'a>>,

    trie_node: VanillaTrieNode<MerkleHash>,
    // path_start_steps is changed when compressed path changes happen, but it
    // doesn't matter because it only happens to node removed from current MPT
    // path.
    path_start_steps: u16,
    // full_path_to_node is changed when combining compressed path.
    // But it doesn't matter because when it happens it's already
    // popped out from current MPT path.
    full_path_to_node: CompressedPathRaw,
    // The path_db_key changes when breaking a compressed path.
    // The path_db_key must be corrected before writing out the node.
    path_db_key: CompressedPathRaw,

    next_child_index: u8,

    first_realized_child_index: u8,
    the_first_child: Option<Box<NodeInMerge<'a>>>,

    has_io_error: *const Cell<bool>,
    db_committed: bool,
}

impl<'a> Drop for NodeInMerge<'a> {
    fn drop(&mut self) {
        if !self.get_has_io_error() {
            assert_eq!(
                true,
                self.db_committed,
                "Node {:?}, {:?} uncommitted for mpt merge.",
                self.path_db_key.as_ref(),
                self.trie_node.get_merkle(),
            );
        }
    }
}

impl SetIoError for *const Cell<bool> {
    fn set_has_io_error(&self) { unsafe { &**self }.replace(true); }
}

impl<'a> SetIoError for NodeInMerge<'a> {
    fn set_has_io_error(&self) { unsafe { &*self.has_io_error }.replace(true); }
}

impl<'a> NodeInMerge<'a> {
    fn new_root(
        mpt_merger: &mut MptMerger<'a>, supposed_merkle_root: &MerkleHash,
    ) -> Result<NodeInMerge<'a>> {
        let mut mpts_in_request = mpt_merger.mpts_in_request.take();
        let root_trie_node = mpt_merger.load_node_wrapper(
            mpts_in_request.io_mpts_assumed_owner(),
            &CompressedPathRaw::default(),
        )?;

        assert_eq!(
            root_trie_node.get_merkle(),
            supposed_merkle_root,
            "loaded root trie node merkle hash {:?} != supposed merkle hash {:?}",
            root_trie_node.get_merkle(),
            supposed_merkle_root,
        );

        Ok(Self {
            mpts_in_request,
            trie_node: root_trie_node,
            path_start_steps: 0,
            full_path_to_node: Default::default(),
            path_db_key: Default::default(),
            next_child_index: 0,
            first_realized_child_index: 0,
            the_first_child: None,
            has_io_error: &mpt_merger.io_error,
            db_committed: false,
        })
    }

    fn new_loaded(
        parent_node: &NodeInMerge<'a>,
        mut mpts_in_request: Option<MptsInRequest<'a>>, node_child_index: u8,
        supposed_merkle_root: &MerkleHash,
    ) -> Result<NodeInMerge<'a>>
    {
        let path_db_key = CompressedPathRaw::concat(
            &parent_node.full_path_to_node,
            node_child_index,
            &CompressedPathRaw::default(),
        );

        let trie_node = parent_node.load_node_wrapper(
            mpts_in_request.io_mpts_assumed_owner(),
            &path_db_key,
        )?;
        assert_eq!(
            trie_node.get_merkle(),
            supposed_merkle_root,
            "loaded trie node merkle hash {:?} != supposed merkle hash {:?}",
            trie_node.get_merkle(),
            supposed_merkle_root,
        );

        let full_path_to_node = CompressedPathRaw::concat(
            &parent_node.full_path_to_node,
            node_child_index,
            &trie_node.compressed_path_ref(),
        );

        Ok(Self {
            mpts_in_request,
            trie_node,
            path_start_steps: parent_node.full_path_to_node.path_steps() + 1,
            full_path_to_node,
            path_db_key,
            next_child_index: 0,
            first_realized_child_index: 0,
            the_first_child: None,
            has_io_error: parent_node.has_io_error,
            db_committed: false,
        })
    }

    fn new(
        trie_node: VanillaTrieNode<MerkleHash>,
        parent_node: &mut NodeInMerge<'a>,
        child_index: u8,
        // path_db_key: CompressedPathRaw,
    ) -> NodeInMerge<'a>
    {
        let full_path_to_node = CompressedPathRaw::concat(
            &parent_node.full_path_to_node,
            child_index,
            &trie_node.compressed_path_ref(),
        );
        Self {
            mpts_in_request: parent_node.mpts_in_request.take(),
            trie_node,
            path_start_steps: parent_node.full_path_to_node.path_steps() + 1,
            full_path_to_node,
            path_db_key: CompressedPathRaw::concat(
                &parent_node.full_path_to_node,
                child_index,
                &CompressedPathRaw::default(),
            ),
            next_child_index: 0,
            first_realized_child_index: 0,
            the_first_child: None,
            has_io_error: parent_node.has_io_error,
            db_committed: false,
        }
    }

    fn get_has_io_error(&self) -> bool { unsafe { &*self.has_io_error }.get() }

    fn write_out(mut self) -> Result<()> {
        // There is nothing to worry about for path_db_key changes in case of
        // path compression changes, because db changes is as simple as
        // data overwriting / deletion / creation.
        if self.is_node_empty() {
            // In-place mode.
            let io_mpts = self.mpts_in_request.io_mpts_assumed_owner();
            if io_mpts.maybe_readonly_mpt.is_none() {
                let result = io_mpts.out_mpt.delete_node(&self.path_db_key);
                if result.is_err() {
                    self.set_has_io_error();
                    return result;
                }
            }
        } else {
            let result = self
                .mpts_in_request
                .io_mpts_assumed_owner()
                .out_mpt
                .write_node(&self.path_db_key, &self.trie_node);
            if result.is_err() {
                self.set_has_io_error();
                return result;
            }
        }

        self.db_committed = true;
        Ok(())
    }

    fn commit(mut self, parent: &mut NodeInMerge<'a>) -> Result<()> {
        self.skip_till_child_index(CHILDREN_COUNT as u8)?;
        if !self.is_node_empty() {
            match self.the_first_child.take() {
                Some(child) => {
                    // Handle path compression.
                    if !self.trie_node.has_value()
                        && self.trie_node.get_children_count() == 1
                    {
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
                            mem::replace(
                                child_trie_node,
                                VanillaTrieNode::default(),
                            ),
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
            Self::write_out_pending_child(&mut self.the_first_child)?;
        }

        let merkle = self.compute_merkle();
        self.write_out()?;
        Ok(merkle)
    }

    fn skip_till_child_index(&mut self, child_index: u8) -> Result<()> {
        for (this_child_index, this_child_node_merkle_ref) in self
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
                        let mpts_in_request = self.mpts_in_request.take();
                        let mut child_node = NodeInMerge::new_loaded(
                            self,
                            mpts_in_request,
                            this_child_index,
                            this_child_node_merkle_ref,
                        )?;
                        // Save-as mode.
                        if child_node
                            .mpts_in_request
                            .io_mpts_assumed_owner()
                            .maybe_readonly_mpt
                            .is_some()
                        {
                            MptMerger::copy_subtree_without_root(
                                &mut child_node,
                            )?;
                        }
                        self.the_first_child = Some(Box::new(child_node));
                    } else {
                        // There are more than one child. Path compression is
                        // unnecessary.
                        Self::write_out_pending_child(
                            &mut self.the_first_child,
                        )?;
                        // Save-as mode.
                        if self
                            .mpts_in_request
                            .io_mpts_assumed_owner()
                            .maybe_readonly_mpt
                            .is_some()
                        {
                            let mpts_in_request = self.mpts_in_request.take();
                            let mut child_node = NodeInMerge::new_loaded(
                                self,
                                mpts_in_request,
                                this_child_index,
                                this_child_node_merkle_ref,
                            )?;
                            MptMerger::copy_subtree_without_root(
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

    fn open_child_index(
        &mut self, child_index: u8,
    ) -> Result<Option<NodeInMerge<'a>>> {
        self.skip_till_child_index(child_index)?;
        self.next_child_index = child_index;

        match self
            .trie_node
            .get_children_table_ref()
            .get_child(child_index)
        {
            None => Ok(None),
            Some(supposed_merkle_hash) => {
                let mpts_in_request = self.mpts_in_request.take();
                Ok(Some(NodeInMerge::new_loaded(
                    self,
                    mpts_in_request,
                    child_index,
                    &supposed_merkle_hash,
                )?))
            }
        }
    }

    fn set_concluded_child(
        &mut self, child_node: NodeInMerge<'a>,
    ) -> Result<()> {
        if !child_node.is_node_empty() {
            // The safety is guaranteed by condition.
            unsafe {
                self.trie_node.replace_child_unchecked(
                    self.next_child_index,
                    child_node.trie_node.get_merkle(),
                )
            };

            // The node won't merge with its first children, because either the
            // node has value, or the child node is the second child. The
            // assumption here is that in db and rust string comparison a string
            // that is a prefix of another string is considered smaller.
            if self.trie_node.has_value() {
                child_node.write_out()?;
            } else if self.first_realized_child_index != 0 {
                Self::write_out_pending_child(&mut self.the_first_child)?;
                child_node.write_out()?;
            } else {
                // This child is the first realized child.
                self.first_realized_child_index = self.next_child_index;
                self.the_first_child = Some(Box::new(child_node));
            }
        } else {
            child_node.write_out()?;

            // The safety is guaranteed by condition.
            unsafe {
                self.trie_node.delete_child_unchecked(self.next_child_index)
            };
        }
        self.next_child_index += 1;
        Ok(())
    }

    fn write_out_pending_child(
        the_first_child: &mut Option<Box<NodeInMerge<'a>>>,
    ) -> Result<()> {
        if the_first_child.is_some() {
            the_first_child.take().unwrap().write_out()
        } else {
            Ok(())
        }
    }

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

struct MptMergerGetChild {}

static MPT_MERGER_GET_CHILD: MptMergerGetChild = MptMergerGetChild {};

impl<'node> GetChildTrait<'node> for MptMergerGetChild {
    type ChildIdType = ();

    fn get_child(&'node self, _child_index: u8) -> Option<()> { None }
}

enum MptMergerPopNodesRemaining<'key> {
    Arrived,
    Descent {
        child_index: u8,
        key_remaining: &'key [u8],
    },
    PathDiverted(WalkStop<'key, ()>),
}

impl<'a> MptMerger<'a> {
    pub fn new(
        maybe_readonly_mpt: Option<&'a mut dyn SnapshotMptTraitReadOnly>,
        out_mpt: &'a mut dyn SnapshotMptTraitSingleWriter,
    ) -> Self
    {
        Self {
            mpts_in_request: Some(MptsInRequest {
                maybe_readonly_mpt,
                out_mpt,
            }),
            io_error: Cell::new(false),
            path_nodes: vec![],
        }
    }

    fn pop_root(&mut self) -> Result<MerkleHash> {
        self.path_nodes.pop().unwrap().commit_root()
    }

    fn pop_one_node(&mut self) -> Result<()> {
        let node = self.path_nodes.pop().unwrap();
        node.commit(self.path_nodes.last_mut().unwrap())
    }

    fn pop_nodes(&mut self, target_key_steps: u16) -> Result<()> {
        // unwrap is fine because the first node is root and it will never be
        // popped.
        while self.path_nodes.last().unwrap().path_start_steps
            > target_key_steps
        {
            self.pop_one_node()?
        }
        Ok(())
    }

    fn prepare_path_for_key<'k, AM: access_mode::AccessMode>(
        &mut self, key: &'k [u8],
    ) -> Result<MptMergerPopNodesRemaining<'k>> {
        match walk::<access_mode::Write, _>(
            key,
            &self.path_nodes.last().unwrap().full_path_to_node,
            &MPT_MERGER_GET_CHILD,
        ) {
            WalkStop::Arrived => Ok(MptMergerPopNodesRemaining::Arrived),
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
            } => Ok(MptMergerPopNodesRemaining::Descent {
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
                let started_steps = last_node.path_start_steps;
                let last_trie_node = &last_node.trie_node;

                // The beginning of compressed_path is always aligned at full
                // byte.
                let aligned_path_start_offset = started_steps / 2;
                if aligned_path_start_offset * 2
                    + last_trie_node.compressed_path_ref().path_steps()
                    == match_stopped_steps
                {
                    if key_child_index.is_none() {
                        // Arrived
                        Ok(MptMergerPopNodesRemaining::Arrived)
                    } else {
                        Ok(MptMergerPopNodesRemaining::Descent {
                            child_index: key_child_index.unwrap(),
                            key_remaining,
                        })
                    }
                } else {
                    // PathDiverted
                    if AM::is_read_only() {
                        Ok(MptMergerPopNodesRemaining::PathDiverted(
                            WalkStop::path_diverted_uninitialized(),
                        ))
                    } else {
                        let actual_matched_path = CompressedPathRaw::new(
                            &last_node.full_path_to_node.path_slice()
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

                        Ok(MptMergerPopNodesRemaining::PathDiverted(
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

    fn insert(&mut self, key: &[u8], value: Box<[u8]>) -> Result<()> {
        let mut maybe_last_step_diverted = None;
        // Hack for lifetime check of value.
        let mut value_last_step_diverted = None;
        match self.prepare_path_for_key::<access_mode::Write>(key)? {
            MptMergerPopNodesRemaining::Arrived => {
                self.path_nodes
                    .last_mut()
                    .unwrap()
                    .trie_node
                    .replace_value_valid(value);
            }
            MptMergerPopNodesRemaining::PathDiverted(path_diverted) => {
                maybe_last_step_diverted = Some(path_diverted);
                value_last_step_diverted = Some(value);
            }
            MptMergerPopNodesRemaining::Descent {
                mut child_index,
                mut key_remaining,
            } => {
                loop {
                    let mut new_node = match self
                        .path_nodes
                        .last_mut()
                        .unwrap()
                        .open_child_index(child_index)?
                    {
                        Some(node) => node,
                        None => {
                            // Create a new node for child_index, key_remaining
                            // and value.
                            let new_node = NodeInMerge::new(
                                VanillaTrieNode::new(
                                    MERKLE_NULL_NODE,
                                    Default::default(),
                                    Some(value),
                                    key_remaining.into(),
                                ),
                                self.path_nodes.last_mut().unwrap(),
                                child_index,
                            );
                            self.path_nodes.push(new_node);
                            return Ok(());
                        }
                    };
                    let next_step = walk::<access_mode::Write, _>(
                        key_remaining,
                        &new_node.trie_node.compressed_path_ref(),
                        &MPT_MERGER_GET_CHILD,
                    );
                    match &next_step {
                        WalkStop::Arrived => {
                            new_node.trie_node.replace_value_valid(value);
                            self.path_nodes.push(new_node);
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
                    maybe_last_step_diverted = Some(next_step);
                    break;
                }
            }
        }
        match maybe_last_step_diverted {
            None => {}
            Some(last_step_diverted) => {
                match last_step_diverted {
                    WalkStop::PathDiverted {
                        key_child_index,
                        key_remaining,
                        matched_path,
                        unmatched_child_index,
                        unmatched_path_remaining,
                    } => {
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

                        let mut fork_node = NodeInMerge::new(
                            VanillaTrieNode::new(
                                MERKLE_NULL_NODE,
                                VanillaChildrenTable::new_from_one_child(
                                    unmatched_child_index,
                                    &MERKLE_NULL_NODE,
                                ),
                                None,
                                matched_path,
                            ),
                            parent_node,
                            parent_node.next_child_index,
                        );
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

                                fork_node.trie_node.add_new_child_unchecked(
                                    child_index,
                                    &MERKLE_NULL_NODE,
                                );
                                fork_node.next_child_index = child_index;

                                let value_node = NodeInMerge::new(
                                    VanillaTrieNode::new(
                                        MERKLE_NULL_NODE,
                                        Default::default(),
                                        value_last_step_diverted,
                                        key_remaining.into(),
                                    ),
                                    &mut fork_node,
                                    child_index,
                                );

                                self.path_nodes.push(fork_node);
                                self.path_nodes.push(value_node);
                            },
                            None => {
                                fork_node.trie_node.replace_value_valid(
                                    value_last_step_diverted.unwrap(),
                                );
                                last_node.commit(&mut fork_node)?;

                                self.path_nodes.push(fork_node);
                            }
                        }
                    }
                    _ => unsafe { unreachable_unchecked() },
                }
            }
        }
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<()> {
        // The access_mode is Write here because we need the diverted path
        // information.
        match self.prepare_path_for_key::<access_mode::Write>(key)? {
            MptMergerPopNodesRemaining::Arrived => {
                let last_node = self.path_nodes.last_mut().unwrap();
                if last_node.trie_node.has_value() {
                    unsafe {
                        last_node.trie_node.delete_value_unchecked();
                    }
                // The action here is as simple as delete the value. It
                // seems tricky if there is no children left, or if
                // there is only one children left. Actually, the
                // deletion of a node value happens before all subtree
                // actions. The skip_till_child_index method will take
                // care of all children, the committing will take care
                // of path merge and node deletion.
                } else {
                    warn!(
                            "In MPT merging, non-existing key {:?} is asked to be deleted.",
                            key);
                }
            }
            MptMergerPopNodesRemaining::PathDiverted(_) => {
                warn!(
                    "In MPT merging, non-existing key {:?} is asked to be deleted.",
                    key);
            }
            MptMergerPopNodesRemaining::Descent {
                mut child_index,
                mut key_remaining,
            } => {
                loop {
                    let last_node = self.path_nodes.last_mut().unwrap();
                    let new_node = match last_node
                        .open_child_index(child_index)?
                    {
                        Some(node) => node,
                        None => {
                            warn!(
                                "In MPT merging, non-existing key {:?} is asked to be deleted.",
                                key);
                            break;
                        }
                    };
                    match walk::<access_mode::Read, _>(
                        key_remaining,
                        &new_node.trie_node.compressed_path_ref(),
                        &MPT_MERGER_GET_CHILD,
                    ) {
                        WalkStop::Arrived => {
                            if new_node.trie_node.has_value() {
                                unsafe {
                                    last_node
                                        .trie_node
                                        .delete_value_unchecked();
                                }
                            } else {
                                warn!(
                                    "In MPT merging, non-existing key {:?} is asked to be deleted.",
                                    key);
                            }
                            self.path_nodes.push(new_node);
                            break;
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
                            child_index = new_child_index;
                            key_remaining = new_key_remaining;
                            continue;
                        }
                        WalkStop::PathDiverted { .. } => {
                            warn!(
                                "In MPT merging, non-existing key {:?} is asked to be deleted.",
                                key);
                            self.path_nodes.push(new_node);
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<MerkleHash> {
        self.pop_nodes(0)?;
        self.pop_root()
    }

    fn get_merkle_root_before_merge(&self) -> &MerkleHash {
        let io_mpts = self.mpts_in_request.io_mpts_readonly_assumed_owner();
        if io_mpts.maybe_readonly_mpt.is_some() {
            io_mpts
                .maybe_readonly_mpt
                .as_ref()
                .unwrap()
                .get_merkle_root()
        } else {
            io_mpts.out_mpt.get_merkle_root()
        }
    }

    // TODO(yz): Invent a trait for inserter to generalize.
    pub fn merge(&mut self, inserter: &DeltaMptInserter) -> Result<MerkleHash> {
        // Load root node.
        let merkle_root_before_merge =
            self.get_merkle_root_before_merge().clone();
        let root_node = NodeInMerge::new_root(self, &merkle_root_before_merge)?;
        self.path_nodes.push(root_node);

        struct Merger<'x, 'a: 'x> {
            merger: &'x mut MptMerger<'a>,
        };

        impl<'x, 'a: 'x> Merger<'x, 'a> {
            fn merger_mut(&mut self) -> &mut MptMerger<'a> { self.merger }
        }

        impl<'x, 'a: 'x> KVInserter<(Vec<u8>, Box<[u8]>)> for Merger<'x, 'a> {
            fn push(&mut self, v: (Vec<u8>, Box<[u8]>)) -> Result<()> {
                let (key, value) = v;
                if value.len() > 0 {
                    self.merger_mut().insert(&key, value)?;
                } else {
                    self.merger_mut().delete(&key)?;
                }
                Ok(())
            }
        }

        inserter.iterate(Merger { merger: self })?;

        self.finish()
    }

    // Will be modified and used when syncing snapshot.
    #[allow(unused)]
    /// The iterators operate on key, value store.
    pub fn merge_insertion_deletion_separated<'k>(
        &mut self, mut delete_keys_iter: impl Iterator<Item = &'k [u8]>,
        mut insert_keys_iter: impl Iterator<Item = (&'k [u8], Box<[u8]>)>,
    ) -> Result<MerkleHash>
    {
        // Load root node.
        let merkle_root_before_merge =
            self.get_merkle_root_before_merge().clone();
        let root_node = NodeInMerge::new_root(self, &merkle_root_before_merge)?;
        self.path_nodes.push(root_node);

        let mut key_to_delete = delete_keys_iter.next();
        let mut key_value_to_insert = insert_keys_iter.next();

        loop {
            if key_to_delete.is_none() {
                if key_value_to_insert.is_some() {
                    let (key, value) = key_value_to_insert.unwrap();
                    self.insert(key, value)?;
                    while let Some((key, value)) = insert_keys_iter.next() {
                        self.insert(key, value)?;
                    }
                    break;
                }
            };

            if key_value_to_insert.is_none() {
                if key_to_delete.is_some() {
                    self.delete(key_to_delete.as_ref().unwrap())?;
                    while let Some(key) = delete_keys_iter.next() {
                        self.delete(key)?;
                    }
                    break;
                }
            }

            // In a diff, if there is a deletion of the same key of a insertion,
            // delete only happens before the insertion because the inserted key
            // value must present in the final merged result for it to be in the
            // diff.
            let key_delete = key_to_delete.as_ref().unwrap();
            let key_insert = &key_value_to_insert.as_ref().unwrap().0;
            if key_delete <= key_insert {
                self.delete(key_delete)?;
                key_to_delete = delete_keys_iter.next();
            } else {
                self.insert(key_insert, key_value_to_insert.unwrap().1)?;
                key_value_to_insert = insert_keys_iter.next();
            }
        }

        self.finish()
    }
}

use super::{
    super::{
        super::{
            super::storage_db::snapshot_mpt::{
                SnapshotMptTraitReadOnly, SnapshotMptTraitSingleWriter,
            },
            errors::*,
            storage_manager::DeltaMptInserter,
        },
        cache::algorithm::CacheAlgoDataTrait,
    },
    children_table::*,
    compressed_path::CompressedPathTrait,
    cow_node_ref::KVInserter,
    trie_node::{TrieNodeTrait, VanillaTrieNode},
    walk::*,
    CompressedPathRaw,
};
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use std::{cell::Cell, hint::unreachable_unchecked, mem, vec::Vec};
