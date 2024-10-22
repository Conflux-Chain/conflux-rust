use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};

pub const NULL: usize = !0;

impl<Ext: Default> Default for BaseNode<Ext> {
    fn default() -> Self {
        Self {
            parent: NULL,
            child: [NULL, NULL],
            value: 0,
            min: 0,
            delta: 0,
            payload: Ext::default(),
        }
    }
}

#[derive(Clone, Debug)]
struct BaseNode<Ext> {
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
    payload: Ext,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Unit;

#[derive(Debug, Clone, Copy)]
pub struct PathLength {
    size: usize,
}
impl Default for PathLength {
    fn default() -> Self { Self { size: 1 } }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Caterpillar {
    caterpillar_value: i128,
    caterpillar_delta: i128,
}

pub struct LinkCutTree<Ext> {
    tree: Vec<BaseNode<Ext>>,
}

impl<Ext: Update + DeltaAndPreferredChild + Clone + Default> LinkCutTree<Ext> {
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

    pub fn new() -> Self { Self { tree: Vec::new() } }

    pub fn size(&self) -> usize { self.tree.len() }

    pub fn make_tree(&mut self, v: usize) {
        if self.tree.len() <= v {
            self.tree.resize(v + 1, BaseNode::<Ext>::default());
        } else {
            self.tree[v] = BaseNode::<Ext>::default();
        }
    }

    pub fn lca(&mut self, v: usize, w: usize) -> usize {
        self.access(v);
        self.access(w)
    }

    pub fn set(&mut self, v: usize, value: i128) {
        self.access(v);

        self.tree[v].value = value;
        self.update(v);
    }

    pub fn path_apply(&mut self, v: usize, delta: i128) {
        self.access(v);

        self.tree[v].value += delta;
        self.tree[v].delta += delta;
        self.tree[v].min += delta;
    }

    pub fn path_aggregate(&mut self, v: usize) -> i128 {
        self.access(v);

        self.tree[v].min
    }

    pub fn path_aggregate_chop(&mut self, v: usize, u: usize) -> i128 {
        self.access(v);
        self.splay(u);
        let right_c = self.tree[u].child[1];
        assert_ne!(right_c, NULL);
        self.update(right_c);
        self.tree[right_c].min
    }

    pub fn get(&mut self, v: usize) -> i128 {
        self.access(v);

        self.tree[v].value
    }

    fn update(&mut self, o: usize) { Ext::update(self, o) }

    fn apply_delta(&mut self, o: usize) { Ext::apply_delta(self, o) }

    fn append_preferred_child(&mut self, o: usize, u: usize) {
        Ext::append_preferred_child(self, o, u)
    }

    fn remove_preferred_child(&mut self, o: usize) {
        Ext::remove_preferred_child(self, o)
    }
}

impl<Ext: Link> LinkCutTree<Ext> {
    pub fn split_root(&mut self, parent: usize, v: usize) {
        Ext::split_root(self, parent, v)
    }

    /// make `w` as a new child of `v`, make sure `w` is the root of a
    /// Auxiliary Tree
    pub fn link(&mut self, v: usize, w: usize) { Ext::link(self, v, w) }
}

pub trait DeltaAndPreferredChild: Update + Sized {
    /// Apply `delta` to children in a Auxiliary Tree.
    /// This clears the `delta` of `o`.
    fn apply_delta(tree: &mut LinkCutTree<Self>, o: usize) {
        if tree.tree[o].delta != 0 {
            for i in 0..2 {
                let c = tree.tree[o].child[i];
                if c != NULL {
                    tree.tree[c].delta += tree.tree[o].delta;
                    tree.tree[c].value += tree.tree[o].delta;
                    tree.tree[c].min += tree.tree[o].delta;
                }
            }
            tree.tree[o].delta = 0;
        }
    }

    /// remove the preferred child of node `o` in its preferred path
    fn remove_preferred_child(tree: &mut LinkCutTree<Self>, o: usize) {
        tree.splay(o);
        tree.tree[o].child[1] = NULL;
    }

    /// concat two preferred path contains node `o` and node `u`, make
    /// sure that `remove_preferred_child(o)` was called right before
    fn append_preferred_child(
        tree: &mut LinkCutTree<Self>, o: usize, u: usize,
    ) {
        tree.set_child(o, u, 1);
        Update::update(tree, o);
    }
}

impl DeltaAndPreferredChild for PathLength {}
impl DeltaAndPreferredChild for Unit {}

pub trait Update: Clone + Default + Sized {
    /// Assumption: `delta` of `o` must be 0, i.e.,
    /// apply_delta() must be invoked for `o` before invoking update()
    fn update(tree: &mut LinkCutTree<Self>, o: usize) {
        tree.tree[o].min = tree.tree[o].value;

        for i in 0..2 {
            let child = tree.tree[o].child[i];
            if child != NULL {
                if tree.tree[o].min > tree.tree[child].min {
                    tree.tree[o].min = tree.tree[child].min;
                }
            }
        }
    }
}

impl Update for Caterpillar {}
impl Update for Unit {}

pub trait Link: DeltaAndPreferredChild + Update + Sized {
    fn split_root(tree: &mut LinkCutTree<Self>, parent: usize, v: usize) {
        tree.access(parent);
        tree.splay(v);
        assert_eq!(tree.tree[v].parent, parent);
        tree.tree[v].parent = NULL;
    }

    /// make `w` as a new child of `v`, make sure `w` is the root of a
    /// Auxiliary Tree
    fn link(tree: &mut LinkCutTree<Self>, v: usize, w: usize) {
        if v == NULL || w == NULL {
            return;
        }
        tree.access(v);
        tree.access(w);
        tree.tree[w].parent = v;
    }
}

impl Link for PathLength {}
impl Link for Unit {}

impl<Ext> MallocSizeOf for LinkCutTree<Ext> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.tree.size_of(ops)
    }
}

impl<Ext> MallocSizeOf for BaseNode<Ext> {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl Update for PathLength {
    #[inline]
    fn update(tree: &mut LinkCutTree<Self>, o: usize) {
        tree.tree[o].payload.size = 1;
        tree.tree[o].min = tree.tree[o].value;
        for i in 0..2 {
            let child = tree.tree[o].child[i];
            if child != NULL {
                tree.tree[o].payload.size += tree.tree[child].payload.size;
                if tree.tree[o].min > tree.tree[child].min {
                    tree.tree[o].min = tree.tree[child].min;
                }
            }
        }
    }
}

impl LinkCutTree<PathLength> {
    pub fn ancestor_at(&mut self, v: usize, at: usize) -> usize {
        self.access(v);

        let mut u = self.tree[v].child[0];
        let size = if u == NULL {
            0
        } else {
            self.tree[u].payload.size
        };
        let mut at = at;

        if at < size {
            loop {
                let w = self.tree[u].child[0];
                let size = if w == NULL {
                    0
                } else {
                    self.tree[w].payload.size
                };
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

impl DeltaAndPreferredChild for Caterpillar {
    /// apply `delta` and `caterpillar_delta` to children in a Auxiliary Tree
    #[inline]
    fn apply_delta(tree: &mut LinkCutTree<Self>, o: usize) {
        if tree.tree[o].delta != 0 {
            for i in 0..2 {
                let c = tree.tree[o].child[i];
                if c != NULL {
                    tree.tree[c].delta += tree.tree[o].delta;
                    tree.tree[c].value += tree.tree[o].delta;
                    tree.tree[c].min += tree.tree[o].delta;
                }
            }
            tree.tree[o].delta = 0;
        }
        if tree.tree[o].payload.caterpillar_delta != 0 {
            for i in 0..2 {
                let c = tree.tree[o].child[i];
                if c != NULL {
                    tree.tree[c].payload.caterpillar_delta +=
                        tree.tree[o].payload.caterpillar_delta;
                    tree.tree[c].payload.caterpillar_value +=
                        tree.tree[o].payload.caterpillar_delta;
                }
            }
            tree.tree[o].payload.caterpillar_delta = 0;
        }
    }

    /// remove the preferred child of node `o` in its preferred path
    fn remove_preferred_child(tree: &mut LinkCutTree<Self>, o: usize) {
        tree.splay(o);
        let mut u = tree.tree[o].child[1];
        tree.tree[o].child[1] = NULL;
        if u != NULL {
            while tree.tree[u].child[0] != NULL {
                u = tree.tree[u].child[0];
            }
            tree.splay(u);
            assert_eq!(tree.tree[u].parent, o);
            tree.tree[u].value -= tree.tree[o].payload.caterpillar_value;
            Update::update(tree, u);
        }
    }

    /// concat two preferred path contains node `o` and node `u`, make sure that
    /// `remove_preferred_child(o)` was called right before
    fn append_preferred_child(
        tree: &mut LinkCutTree<Self>, o: usize, u: usize,
    ) {
        let mut u = u;
        if u != NULL {
            // find leftmost node
            while tree.tree[u].child[0] != NULL {
                u = tree.tree[u].child[0];
            }
            tree.splay(u);
            assert_eq!(tree.tree[u].parent, o);
            tree.tree[u].value += tree.tree[o].payload.caterpillar_value;
            Update::update(tree, u);
        }
        tree.set_child(o, u, 1);
        Update::update(tree, o);
    }
}

impl LinkCutTree<Caterpillar> {
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
    pub fn caterpillar_apply(&mut self, v: usize, caterpillar_delta: i128) {
        self.access(v);

        self.tree[v].value += caterpillar_delta;
        self.tree[v].delta += caterpillar_delta;
        self.tree[v].min += caterpillar_delta;
        self.tree[v].payload.caterpillar_delta += caterpillar_delta;
        self.tree[v].payload.caterpillar_value += caterpillar_delta;
    }
}

impl Link for Caterpillar {
    fn split_root(
        tree: &mut LinkCutTree<Caterpillar>, parent: usize, v: usize,
    ) {
        tree.access(parent);
        tree.splay(v);
        assert_eq!(tree.tree[v].parent, parent);
        tree.tree[v].parent = NULL;
        tree.tree[v].value += tree.tree[parent].payload.caterpillar_value;
    }

    /// make `w` as a new child of `v`, make sure `w` is the root of a Auxiliary
    /// Tree
    fn link(tree: &mut LinkCutTree<Caterpillar>, v: usize, w: usize) {
        if v == NULL || w == NULL {
            return;
        }
        tree.access(v);
        tree.access(w);
        tree.tree[w].parent = v;
        tree.tree[w].value -= tree.tree[v].payload.caterpillar_value;
    }
}
