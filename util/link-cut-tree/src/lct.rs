use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};

pub const NULL: usize = !0;

pub trait DefaultLinkCutTreeTrait {
    fn new() -> Self;

    fn size(&self) -> usize;

    fn make_tree(&mut self, v: usize);

    fn lca(&mut self, v: usize, w: usize) -> usize;

    fn set(&mut self, v: usize, value: i128);

    fn path_apply(&mut self, v: usize, delta: i128);

    fn path_aggregate(&mut self, v: usize) -> i128;

    fn path_aggregate_chop(&mut self, v: usize, u: usize) -> i128;

    fn get(&mut self, v: usize) -> i128;
}

pub trait SizeLinkCutTreeTrait {
    fn ancestor_at(&mut self, _v: usize, _at: usize) -> usize {
        unimplemented!("ancestor_at is not implemented");
    }
}

pub trait CaterpillarLinkCutTreeTrait {
    fn link(&mut self, v: usize, w: usize);

    fn split_root(&mut self, parent: usize, v: usize);

    fn caterpillar_apply(&mut self, _v: usize, _caterpillar_delta: i128) {
        unimplemented!("caterpillar_apply is not implemented");
    }
}

macro_rules! impl_default_for_lct_node {
    ($name: ident, $($element: ident: $value: expr),*) => {
        impl Default for $name {
            fn default() -> Self {
                Self {
                    parent: NULL,
                    child: [NULL, NULL],
                    value: 0,
                    min: 0,
                    delta: 0,
                    $($element: $value),*
                }
            }
        }
    }
}

macro_rules! define_lct_node {
    ($name:ident, $($element:ident : $ty:ty),*) => {
        #[derive(Clone, Debug)]
        struct $name {
            /// if current node is the root node of an Auxiliary Tree, parent
            /// points to the parent node in actual tree, otherwise parent
            /// points to the parent node in a Auxiliary Tree
            parent: usize,
            /// left and right children in the Auxiliary Tree
            child: [usize; 2],
            /// if node `o` is the topmost node in a preferred path,
            /// and let `r` be the root node of the Auxiliary Tree,
            /// the actual value of `o` equals to
            /// `o.value + r.parent.caterpillar_value`,
            /// otherwise the actual value equals to `o.value`
            value: i128,
            /// minimum subtree value of current node in the Auxiliary Tree
            min: i128,
            /// The delta needs to be applied to `value` and `min` of the
            /// nodes in the subtree of the Auxiliary Tree rooted at this
            /// node excluding the node itself.
            delta: i128,
            $($element: $ty),*
        }
    };
}

macro_rules! construct_link_cut_node {
    (MinNode) => {
        define_lct_node!(MinNode, );
        impl_default_for_lct_node!(MinNode, );
    };
    (SizeMinNode) => {
        // subtree size of current node in the Auxiliary Tree
        define_lct_node!(SizeMinNode, size: usize);
        impl_default_for_lct_node!(SizeMinNode, size: 1);
    };
    (CaterpillarMinNode) => {
        define_lct_node!(CaterpillarMinNode, caterpillar_value: i128, caterpillar_delta: i128);
        impl_default_for_lct_node!(CaterpillarMinNode, caterpillar_value: 0, caterpillar_delta: 0);
    }
}

macro_rules! construct_link_cut_tree {
    ($lct_name:ident, $lct_node_name:ident) => {
        construct_link_cut_node!($lct_node_name);

        pub struct $lct_name {
            tree: Vec<$lct_node_name>,
        }

        impl $lct_name {
            /// return whether node `o` is the left or right child of its
            /// parent (left: 0; right: 1)
            /// Assumption:
            ///   If `o` is the root node of an Auxiliary Tree, the return
            ///   value is meaningless.
            #[inline]
            fn direction(&mut self, o: usize) -> usize {
                let parent = self.tree[o].parent;
                if parent == NULL {
                    0
                } else {
                    (self.tree[parent].child[1] == o) as usize
                }
            }

            /// whether node `o` is the root of an Auxiliary Tree
            /// Assumption:
            ///   The children of a leaf node of an Auxiliary Tree are NULLs.
            #[inline]
            fn is_root(&mut self, o: usize) -> bool {
                let parent = self.tree[o].parent;
                parent == NULL
                    || (self.tree[parent].child[0] != o
                        && self.tree[parent].child[1] != o)
            }

            /// make node `c` the child of node `o` in the Auxiliary Tree,
            /// `d = 0` means left child, `d = 1` means right child.
            #[inline]
            fn set_child(&mut self, o: usize, c: usize, d: usize) {
                self.tree[o].child[d] = c;
                if c != NULL {
                    self.tree[c].parent = o;
                }
            }

            /// make node `o` closer to root, there are 4 kinds of rotate
            ///        gp                gp
            ///       /  \              /  \
            ///     p(o)  T4          o(p) T4
            ///     / \               / \
            ///   o(p) T3     <==>   T1 p(o)
            ///   / \                   / \
            ///  T1 T2                 T2 T3
            ///
            ///    gp                 gp
            ///   /  \               /  \
            ///  T1  p(o)           T1  o(p)
            ///      / \                / \
            ///    o(p) T4    <==>     T2 p(o)
            ///    / \                    / \
            ///   T2 T3                  T3 T4
            ///
            /// Assumption:
            ///   apply_delta() must be invoked for parent of `o` before.
            fn rotate(&mut self, o: usize) {
                if o == NULL || self.is_root(o) {
                    return;
                }
                let parent = self.tree[o].parent;
                let grandparent = self.tree[parent].parent;
                let parent_is_root = self.is_root(parent);
                let d1 = self.direction(o);
                let d2 = self.direction(parent);
                self.set_child(parent, self.tree[o].child[1 - d1], d1);
                self.set_child(o, parent, 1 - d1);
                if !parent_is_root {
                    self.set_child(grandparent, o, d2);
                }
                self.tree[o].parent = grandparent;
                self.update(parent);
            }

            /// after splay, node `o` will become the root of a Auxiliary Tree
            /// the `delta` and `caterpillar_delta` of node `o` will be cleared
            /// 1. parent is root: zig
            /// 2. gp -> p -> o the same direction: zig-zig
            /// 3. gp -> p -> o not the same direction: zig-zag
            fn splay(&mut self, o: usize) {
                assert!(o != NULL);
                // apply `delta` and `caterpillar_delta` along the path
                // from `o` to the root of the Auxiliary Tree
                let mut path = Vec::new();
                let mut p = o;
                while !self.is_root(p) {
                    path.push(p);
                    p = self.tree[p].parent;
                }
                path.push(p);
                path.reverse();
                for v in path {
                    self.apply_delta(v);
                }
                while !self.is_root(o) {
                    let parent = self.tree[o].parent;
                    if !self.is_root(parent) {
                        if self.direction(o) == self.direction(parent) {
                            self.rotate(parent);
                        } else {
                            self.rotate(o);
                        }
                    }
                    self.rotate(o);
                }
                self.update(o);
            }

            /// make the path from node `o` to the root become a preferred path
            /// return
            fn access(&mut self, o: usize) -> usize {
                assert!(o != NULL);
                let mut last = NULL;
                let mut now = o;
                while now != NULL {
                    self.remove_preferred_child(now);
                    self.append_preferred_child(now, last);
                    last = now;
                    now = self.tree[now].parent;
                }
                self.splay(o);

                last
            }
        }

        impl DefaultLinkCutTreeTrait for $lct_name {
            fn new() -> Self {
                Self { tree: Vec::new() }
            }

            fn size(&self) -> usize {
                self.tree.len()
            }

            fn make_tree(&mut self, v: usize) {
                if self.tree.len() <= v {
                    self.tree.resize(v + 1, $lct_node_name::default());
                } else {
                    self.tree[v] = $lct_node_name::default();
                }
            }

            fn lca(&mut self, v: usize, w: usize) -> usize {
                self.access(v);
                self.access(w)
            }

            fn set(&mut self, v: usize, value: i128) {
                self.access(v);

                self.tree[v].value = value;
                self.update(v);
            }

            fn path_apply(&mut self, v: usize, delta: i128) {
                self.access(v);

                self.tree[v].value += delta;
                self.tree[v].delta += delta;
                self.tree[v].min += delta;
            }

            fn path_aggregate(&mut self, v: usize) -> i128 {
                self.access(v);

                self.tree[v].min
            }

            fn path_aggregate_chop(&mut self, v: usize, u: usize) -> i128 {
                self.access(v);
                self.splay(u);
                let right_c = self.tree[u].child[1];
                assert_ne!(right_c, NULL);
                self.update(right_c);
                self.tree[right_c].min
            }

            fn get(&mut self, v: usize) -> i128 {
                self.access(v);

                self.tree[v].value
            }
        }
    };
}

macro_rules! impl_default_lct_func {
    ($lct_name:ident) => {
        impl $lct_name {
            /// Apply `delta` to children in a Auxiliary Tree.
            /// This clears the `delta` of `o`.
            #[inline]
            fn apply_delta(&mut self, o: usize) {
                if self.tree[o].delta != 0 {
                    for i in 0..2 {
                        let c = self.tree[o].child[i];
                        if c != NULL {
                            self.tree[c].delta += self.tree[o].delta;
                            self.tree[c].value += self.tree[o].delta;
                            self.tree[c].min += self.tree[o].delta;
                        }
                    }
                    self.tree[o].delta = 0;
                }
            }

            /// remove the preferred child of node `o` in its preferred path
            fn remove_preferred_child(&mut self, o: usize) {
                self.splay(o);
                self.tree[o].child[1] = NULL;
            }

            /// concat two preferred path contains node `o` and node `u`, make
            /// sure that `remove_preferred_child(o)` was called right before
            fn append_preferred_child(&mut self, o: usize, u: usize) {
                self.set_child(o, u, 1);
                self.update(o);
            }
        }
    };
}

macro_rules! impl_default_update_func {
    ($lct_name:ident) => {
        impl $lct_name {
            /// Assumption: `delta` of `o` must be 0, i.e.,
            /// apply_delta() must be invoked for `o` before invoking update()
            #[inline]
            fn update(&mut self, o: usize) {
                self.tree[o].min = self.tree[o].value;

                for i in 0..2 {
                    let child = self.tree[o].child[i];
                    if child != NULL {
                        if self.tree[o].min > self.tree[child].min {
                            self.tree[o].min = self.tree[child].min;
                        }
                    }
                }
            }
        }
    };
}

macro_rules! impl_default_size_link_cut_tree_trait {
    ($lct_name:ident) => {
        impl SizeLinkCutTreeTrait for $lct_name {}
    };
}

macro_rules! impl_default_caterpillar_link_cut_tree_trait {
    ($lct_name:ident) => {
        impl CaterpillarLinkCutTreeTrait for $lct_name {
            fn split_root(&mut self, parent: usize, v: usize) {
                self.access(parent);
                self.splay(v);
                assert_eq!(self.tree[v].parent, parent);
                self.tree[v].parent = NULL;
            }

            /// make `w` as a new child of `v`, make sure `w` is the root of a
            /// Auxiliary Tree
            fn link(&mut self, v: usize, w: usize) {
                if v == NULL || w == NULL {
                    return;
                }
                self.access(v);
                self.access(w);
                self.tree[w].parent = v;
            }
        }
    };
}

construct_link_cut_tree!(MinLinkCutTreeInner, MinNode);
construct_link_cut_tree!(SizeMinLinkCutTreeInner, SizeMinNode);
construct_link_cut_tree!(CaterpillarMinLinkCutTreeInner, CaterpillarMinNode);

impl_default_update_func!(MinLinkCutTreeInner);
impl_default_update_func!(CaterpillarMinLinkCutTreeInner);

impl_default_size_link_cut_tree_trait!(MinLinkCutTreeInner);
impl_default_size_link_cut_tree_trait!(CaterpillarMinLinkCutTreeInner);

impl_default_lct_func!(MinLinkCutTreeInner);
impl_default_lct_func!(SizeMinLinkCutTreeInner);
impl_default_caterpillar_link_cut_tree_trait!(MinLinkCutTreeInner);
impl_default_caterpillar_link_cut_tree_trait!(SizeMinLinkCutTreeInner);

impl MallocSizeOf for SizeMinLinkCutTreeInner {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.tree.size_of(ops)
    }
}

impl MallocSizeOf for SizeMinNode {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        0
    }
}

impl MallocSizeOf for CaterpillarMinLinkCutTreeInner {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.tree.size_of(ops)
    }
}

impl MallocSizeOf for CaterpillarMinNode {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        0
    }
}

impl SizeMinLinkCutTreeInner {
    #[inline]
    fn update(&mut self, o: usize) {
        self.tree[o].size = 1;
        self.tree[o].min = self.tree[o].value;

        for i in 0..2 {
            let child = self.tree[o].child[i];
            if child != NULL {
                self.tree[o].size += self.tree[child].size;
                if self.tree[o].min > self.tree[child].min {
                    self.tree[o].min = self.tree[child].min;
                }
            }
        }
    }
}

impl SizeLinkCutTreeTrait for SizeMinLinkCutTreeInner {
    fn ancestor_at(&mut self, v: usize, at: usize) -> usize {
        self.access(v);

        let mut u = self.tree[v].child[0];
        let size = if u == NULL { 0 } else { self.tree[u].size };
        let mut at = at;

        if at < size {
            loop {
                let w = self.tree[u].child[0];
                let size = if w == NULL { 0 } else { self.tree[w].size };
                if at < size {
                    u = w;
                } else if at == size {
                    self.splay(u);
                    return u;
                } else {
                    at -= size + 1;
                    u = self.tree[u].child[1];
                }
            }
        } else if at == size {
            return v;
        }

        NULL
    }
}

impl CaterpillarMinLinkCutTreeInner {
    /// apply `delta` and `caterpillar_delta` to children in a Auxiliary Tree
    #[inline]
    fn apply_delta(&mut self, o: usize) {
        if self.tree[o].delta != 0 {
            for i in 0..2 {
                let c = self.tree[o].child[i];
                if c != NULL {
                    self.tree[c].delta += self.tree[o].delta;
                    self.tree[c].value += self.tree[o].delta;
                    self.tree[c].min += self.tree[o].delta;
                }
            }
            self.tree[o].delta = 0;
        }
        if self.tree[o].caterpillar_delta != 0 {
            for i in 0..2 {
                let c = self.tree[o].child[i];
                if c != NULL {
                    self.tree[c].caterpillar_delta +=
                        self.tree[o].caterpillar_delta;
                    self.tree[c].caterpillar_value +=
                        self.tree[o].caterpillar_delta;
                }
            }
            self.tree[o].caterpillar_delta = 0;
        }
    }

    /// remove the preferred child of node `o` in its preferred path
    fn remove_preferred_child(&mut self, o: usize) {
        self.splay(o);
        let mut u = self.tree[o].child[1];
        self.tree[o].child[1] = NULL;
        if u != NULL {
            while self.tree[u].child[0] != NULL {
                u = self.tree[u].child[0];
            }
            self.splay(u);
            assert_eq!(self.tree[u].parent, o);
            self.tree[u].value -= self.tree[o].caterpillar_value;
            self.update(u);
        }
    }

    /// concat two preferred path contains node `o` and node `u`, make sure that
    /// `remove_preferred_child(o)` was called right before
    fn append_preferred_child(&mut self, o: usize, u: usize) {
        let mut u = u;
        if u != NULL {
            // find leftmost node
            while self.tree[u].child[0] != NULL {
                u = self.tree[u].child[0];
            }
            self.splay(u);
            assert_eq!(self.tree[u].parent, o);
            self.tree[u].value += self.tree[o].caterpillar_value;
            self.update(u);
        }
        self.set_child(o, u, 1);
        self.update(o);
    }
}

impl CaterpillarLinkCutTreeTrait for CaterpillarMinLinkCutTreeInner {
    /// ```text
    ///            ||
    ///            V3
    ///         /  ||  \
    ///      V'2   V2  V"2
    ///         /  ||  \
    ///      V'1   V1  V"1
    ///         /  |   \
    ///      V'0   V0  V"0
    ///
    /// In the above figure, we use "/", "|", and "\" to represent light
    /// edges, and "||" to represent heavy edges.
    ///
    /// The caterpillar delta/value represents the caterpillar effect of
    /// a node V on all its children connected to V through light edges.
    /// The caterpillar effect of V on its child connected through heavy
    /// edge should already be applied through the delta/value of the child.
    /// This is because when accessing a node, it must be on the preferred
    /// path and its value should already be the final value with caterpillar
    /// effect integrated.
    ///
    /// Specifically, when calling caterpillar_apply(V1, caterpillar_delta),
    /// The edges between V1 and all its children become light edges.
    /// The caterpillar_value of V1 represents its caterpillar effect on
    /// V'0, V0, and V"0. The caterpillar_delta of V1 helps maintain the
    /// caterpillar effects of V2 on V'1 and V"1, and V3 on V'2 and V"2,
    /// and so on upwards. The value of V1 has already integrated the
    /// caterpillar effect of V2 on it, and the delta of V1 helps maintain
    /// the integrated caterpillar effects of V3 on V2, and so on upwards.
    /// ```
    fn caterpillar_apply(&mut self, v: usize, caterpillar_delta: i128) {
        self.access(v);

        self.tree[v].value += caterpillar_delta;
        self.tree[v].delta += caterpillar_delta;
        self.tree[v].min += caterpillar_delta;
        self.tree[v].caterpillar_delta += caterpillar_delta;
        self.tree[v].caterpillar_value += caterpillar_delta;
    }

    fn split_root(&mut self, parent: usize, v: usize) {
        self.access(parent);
        self.splay(v);
        assert_eq!(self.tree[v].parent, parent);
        self.tree[v].parent = NULL;
        self.tree[v].value += self.tree[parent].caterpillar_value;
    }

    /// make `w` as a new child of `v`, make sure `w` is the root of a Auxiliary
    /// Tree
    fn link(&mut self, v: usize, w: usize) {
        if v == NULL || w == NULL {
            return;
        }
        self.access(v);
        self.access(w);
        self.tree[w].parent = v;
        self.tree[w].value -= self.tree[v].caterpillar_value;
    }
}
