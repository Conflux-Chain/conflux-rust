// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::SignedBigNum;

const NULL: usize = !0;

#[derive(Clone)]
struct MinNode {
    left_child: usize,
    right_child: usize,
    parent: usize,
    path_parent: usize,
    size: usize,
    value: SignedBigNum,
    min: SignedBigNum,
    min_idx: usize,
    delta: SignedBigNum,
    catepillar_value: SignedBigNum,
    catepillar_delta: SignedBigNum,
}

impl Default for MinNode {
    fn default() -> Self {
        MinNode {
            left_child: NULL,
            right_child: NULL,
            parent: NULL,
            path_parent: NULL,
            size: 1,
            value: SignedBigNum::zero(),
            min: SignedBigNum::zero(),
            // We need to set this value to its own index
            min_idx: 0,
            delta: SignedBigNum::zero(),
            catepillar_value: SignedBigNum::zero(),
            catepillar_delta: SignedBigNum::zero(),
        }
    }
}

pub struct MinLinkCutTree {
    tree: Vec<MinNode>,
}

impl MinLinkCutTree {
    pub fn new() -> Self { Self { tree: Vec::new() } }

    pub fn size(&self) -> usize { self.tree.len() }

    pub fn make_tree(&mut self, v: usize) {
        if self.tree.len() <= v {
            let old_len = self.tree.len();
            self.tree.resize(v + 1, MinNode::default());
            for i in old_len..self.tree.len() {
                self.tree[i].min_idx = i;
            }
        }
    }

    fn update(&mut self, v: usize) {
        self.tree[v].size = 1;
        self.tree[v].min = self.tree[v].value;
        self.tree[v].min_idx = v;

        let u = self.tree[v].left_child;
        if u != NULL {
            self.tree[v].size += self.tree[u].size;
            if self.tree[v].min > self.tree[u].min {
                self.tree[v].min = self.tree[u].min;
                self.tree[v].min_idx = self.tree[u].min_idx;
            }
        }
        let w = self.tree[v].right_child;
        if w != NULL {
            self.tree[v].size += self.tree[w].size;
            if self.tree[v].min > self.tree[w].min {
                self.tree[v].min = self.tree[w].min;
                self.tree[v].min_idx = self.tree[w].min_idx;
            }
        }
        self.tree[v].min = self.tree[v].min + self.tree[v].delta;
    }

    fn rotate(&mut self, v: usize) {
        if v == NULL {
            return;
        }
        if self.tree[v].parent == NULL {
            return;
        }

        let parent = self.tree[v].parent;
        let grandparent = self.tree[parent].parent;

        let value =
            self.tree[v].value + self.tree[v].delta + self.tree[parent].delta;
        self.tree[v].value = value;

        let cv = self.tree[v].catepillar_value
            + self.tree[v].catepillar_delta
            + self.tree[parent].catepillar_delta;
        self.tree[v].catepillar_value = cv;

        if self.tree[parent].left_child == v {
            let u = self.tree[v].right_child;
            let w = self.tree[v].left_child;
            self.tree[parent].left_child = u;
            if u != NULL {
                self.tree[u].parent = parent;
                self.tree[u].delta = self.tree[u].delta + self.tree[v].delta;
                self.tree[u].catepillar_delta = self.tree[u].catepillar_delta
                    + self.tree[v].catepillar_delta;
                self.update(u);
            }
            if w != NULL {
                self.tree[w].delta = self.tree[w].delta
                    + self.tree[v].delta
                    + self.tree[parent].delta;
                self.tree[w].catepillar_delta = self.tree[w].catepillar_delta
                    + self.tree[v].catepillar_delta
                    + self.tree[parent].catepillar_delta;
                self.update(w);
            }
            self.tree[v].delta = SignedBigNum::zero();
            self.tree[v].catepillar_delta = SignedBigNum::zero();
            self.tree[v].right_child = parent;
            self.tree[parent].parent = v;
            self.update(parent);
            self.update(v);
        } else {
            let u = self.tree[v].left_child;
            let w = self.tree[v].right_child;
            self.tree[parent].right_child = u;
            if u != NULL {
                self.tree[u].parent = parent;
                self.tree[u].delta = self.tree[u].delta + self.tree[v].delta;
                self.tree[u].catepillar_delta = self.tree[u].catepillar_delta
                    + self.tree[v].catepillar_delta;
                self.update(u);
            }
            if w != NULL {
                self.tree[w].delta = self.tree[w].delta
                    + self.tree[v].delta
                    + self.tree[parent].delta;
                self.tree[w].catepillar_delta = self.tree[w].catepillar_delta
                    + self.tree[v].catepillar_delta
                    + self.tree[parent].catepillar_delta;
                self.update(w);
            }
            self.tree[v].delta = SignedBigNum::zero();
            self.tree[v].catepillar_delta = SignedBigNum::zero();
            self.tree[v].left_child = parent;
            self.tree[parent].parent = v;
            self.update(parent);
            self.update(v);
        }
        self.tree[v].parent = grandparent;
        if grandparent != NULL {
            if self.tree[grandparent].left_child == parent {
                self.tree[grandparent].left_child = v;
            } else {
                self.tree[grandparent].right_child = v;
            }
            self.update(grandparent);
        }
        self.tree[v].path_parent = self.tree[parent].path_parent;
        self.tree[parent].path_parent = NULL;
    }

    fn splay(&mut self, v: usize) {
        if v == NULL {
            return;
        }

        while self.tree[v].parent != NULL {
            let parent = self.tree[v].parent;
            let grandparent = self.tree[parent].parent;
            if grandparent == NULL {
                // zig
                self.rotate(v);
            } else if (self.tree[parent].left_child == v)
                == (self.tree[grandparent].left_child == parent)
            {
                // zig-zig
                self.rotate(parent);
                self.rotate(v);
            } else {
                // zig-zag
                self.rotate(v);
                self.rotate(v);
            }
        }
    }

    fn remove_preferred_child(&mut self, v: usize) {
        if v == NULL {
            return;
        }

        let u = self.tree[v].right_child;
        if u != NULL {
            let mut leftmost = u;
            while self.tree[leftmost].left_child != NULL {
                leftmost = self.tree[leftmost].left_child;
            }

            self.tree[u].path_parent = v;
            self.tree[u].parent = NULL;
            self.splay(leftmost);

            assert_eq!(self.tree[v].catepillar_delta, SignedBigNum::zero());
            self.tree[leftmost].value =
                self.tree[leftmost].value - self.tree[v].catepillar_value;
            self.tree[leftmost].delta =
                self.tree[leftmost].delta + self.tree[v].delta;
            self.tree[leftmost].catepillar_delta = self.tree[leftmost]
                .catepillar_delta
                + self.tree[v].catepillar_delta;
            self.update(leftmost);

            self.tree[v].right_child = NULL;
            assert_eq!(self.tree[leftmost].path_parent, v);
            self.update(v);
        }
    }

    fn access(&mut self, v: usize) -> usize {
        if v == NULL {
            return NULL;
        }

        self.splay(v);
        self.remove_preferred_child(v);

        let mut last = v;

        while self.tree[v].path_parent != NULL {
            let w = self.tree[v].path_parent;
            last = w;

            self.splay(w);
            let u = self.tree[w].right_child;
            if u != NULL {
                let mut leftmost = u;
                while self.tree[leftmost].left_child != NULL {
                    leftmost = self.tree[leftmost].left_child;
                }

                self.tree[u].path_parent = w;
                self.tree[u].parent = NULL;
                self.splay(leftmost);

                assert_eq!(self.tree[w].catepillar_delta, SignedBigNum::zero());
                self.tree[leftmost].value =
                    self.tree[leftmost].value - self.tree[w].catepillar_value;
                self.update(leftmost);

                assert_eq!(self.tree[leftmost].path_parent, w);
            }

            let mut leftmost = v;
            while self.tree[leftmost].left_child != NULL {
                leftmost = self.tree[leftmost].left_child;
            }
            self.splay(leftmost);
            self.tree[leftmost].value =
                self.tree[leftmost].value + self.tree[w].catepillar_value;
            self.update(leftmost);

            self.tree[leftmost].parent = w;
            self.tree[leftmost].path_parent = NULL;

            self.tree[w].right_child = leftmost;
            self.update(w);

            self.splay(v);
        }

        last
    }

    #[allow(dead_code)]
    fn debug(&self, num: usize) {
        for v in 0..num {
            println!("tree[{}]", v);
            println!("\tleft_child={}", self.tree[v].left_child as i64);
            println!("\tright_child={}", self.tree[v].right_child as i64);
            println!("\tparent={}", self.tree[v].parent as i64);
            println!("\tpath_parent={}", self.tree[v].path_parent as i64);
            println!("\tsize={}", self.tree[v].size as i64);
            println!("\tv={:?}", self.tree[v].value);
            println!("\td={:?}", self.tree[v].delta);
            println!("\tcv={:?}", self.tree[v].catepillar_value);
            println!("\tcd={:?}", self.tree[v].catepillar_delta);
        }
    }

    /// Make w a new child of v
    pub fn link(&mut self, v: usize, w: usize) {
        if v == NULL || w == NULL {
            return;
        }

        self.access(w);
        self.tree[w].path_parent = v;
    }

    pub fn lca(&mut self, v: usize, w: usize) -> usize {
        self.access(v);
        self.access(w)
    }

    pub fn ancestor_at(&mut self, v: usize, at: usize) -> usize {
        self.access(v);

        let mut u = self.tree[v].left_child;
        let size = if u == NULL { 0 } else { self.tree[u].size };
        let mut at = at;

        if at < size {
            loop {
                let w = self.tree[u].left_child;
                let size = if w == NULL { 0 } else { self.tree[w].size };
                if at < size {
                    u = w;
                } else if at == size {
                    return u;
                } else {
                    at -= size + 1;
                    u = self.tree[u].right_child;
                }
            }
        } else if at == size {
            return v;
        }

        NULL
    }

    pub fn set(&mut self, v: usize, value: &SignedBigNum) {
        self.access(v);

        self.tree[v].value = *value;
        self.update(v);
    }

    pub fn path_apply(&mut self, v: usize, delta: &SignedBigNum) {
        self.access(v);

        self.tree[v].value += *delta;
        let u = self.tree[v].left_child;
        if u != NULL {
            self.tree[u].delta += *delta;
            self.update(u);
        }
        self.update(v);
    }

    pub fn catepillar_apply(
        &mut self, v: usize, catepillar_delta: &SignedBigNum,
    ) {
        self.access(v);

        self.tree[v].catepillar_value += *catepillar_delta;
        self.tree[v].value += *catepillar_delta;
        let u = self.tree[v].left_child;
        if u != NULL {
            self.tree[u].catepillar_delta += *catepillar_delta;
            self.tree[u].delta += *catepillar_delta;
            self.update(u);
        }
        self.update(v);
    }

    pub fn path_aggregate(&mut self, v: usize) -> SignedBigNum {
        self.access(v);

        self.tree[v].min.clone()
    }

    pub fn path_aggregate_idx(&mut self, v: usize) -> usize {
        self.access(v);

        self.tree[v].min_idx
    }

    pub fn get(&mut self, v: usize) -> SignedBigNum {
        self.access(v);

        self.tree[v].value
    }
}

#[cfg(test)]
mod tests {
    use super::MinLinkCutTree;
    use crate::SignedBigNum;
    use cfx_types::U256;

    #[test]
    fn test_min() {
        let mut tree = MinLinkCutTree::new();

        // 0
        // |\
        // 1 4
        // |\
        // 2 3
        tree.make_tree(0);
        tree.make_tree(1);
        tree.make_tree(2);
        tree.make_tree(3);
        tree.make_tree(4);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);

        tree.set(0, &SignedBigNum::from(U256::from(10)));
        tree.set(1, &SignedBigNum::from(U256::from(9)));
        tree.set(2, &SignedBigNum::from(U256::from(8)));
        tree.set(3, &SignedBigNum::from(U256::from(7)));
        tree.set(4, &SignedBigNum::from(U256::from(6)));

        assert_eq!(tree.path_aggregate(0), SignedBigNum::pos(U256::from(10)));
        assert_eq!(tree.path_aggregate(1), SignedBigNum::pos(U256::from(9)));
        assert_eq!(tree.path_aggregate(2), SignedBigNum::pos(U256::from(8)));
        assert_eq!(tree.path_aggregate(3), SignedBigNum::pos(U256::from(7)));
        assert_eq!(tree.path_aggregate(4), SignedBigNum::pos(U256::from(6)));

        tree.path_apply(1, &SignedBigNum::neg(U256::from(5)));

        assert_eq!(tree.path_aggregate(0), SignedBigNum::pos(U256::from(5)));
        assert_eq!(tree.path_aggregate(1), SignedBigNum::pos(U256::from(4)));
        assert_eq!(tree.path_aggregate(2), SignedBigNum::pos(U256::from(4)));
        assert_eq!(tree.path_aggregate(3), SignedBigNum::pos(U256::from(4)));
        assert_eq!(tree.path_aggregate(4), SignedBigNum::pos(U256::from(5)));
    }

    #[test]
    fn test_lca() {
        let mut tree = MinLinkCutTree::new();

        // 0
        // |\
        // 1 4
        // |\
        // 2 3
        tree.make_tree(0);
        tree.make_tree(1);
        tree.make_tree(2);
        tree.make_tree(3);
        tree.make_tree(4);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);

        assert_eq!(tree.lca(0, 1), 0);
        assert_eq!(tree.lca(2, 3), 1);
        assert_eq!(tree.lca(1, 4), 0);
        assert_eq!(tree.lca(1, 4), 0);
    }

    #[test]
    fn test_get() {
        let mut tree = MinLinkCutTree::new();
        tree.make_tree(0);
        tree.make_tree(1);
        tree.make_tree(2);
        tree.make_tree(3);
        tree.make_tree(4);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);
        tree.path_apply(0, &SignedBigNum::pos(U256::from(1u64)));
        tree.path_apply(1, &SignedBigNum::pos(U256::from(2u64)));
        tree.path_apply(2, &SignedBigNum::pos(U256::from(3u64)));
        tree.path_apply(3, &SignedBigNum::pos(U256::from(4u64)));
        tree.path_apply(4, &SignedBigNum::pos(U256::from(5u64)));

        assert_eq!(tree.get(0), SignedBigNum::pos(U256::from(15u64)));
        assert_eq!(tree.get(1), SignedBigNum::pos(U256::from(9u64)));
        assert_eq!(tree.get(2), SignedBigNum::pos(U256::from(3u64)));
        assert_eq!(tree.get(3), SignedBigNum::pos(U256::from(4u64)));
        assert_eq!(tree.get(4), SignedBigNum::pos(U256::from(5u64)));

        tree.path_apply(4, &SignedBigNum::neg(U256::from(5u64)));
        assert_eq!(tree.get(0), SignedBigNum::pos(U256::from(10u64)));
        assert_eq!(tree.get(1), SignedBigNum::pos(U256::from(9u64)));
        assert_eq!(tree.get(2), SignedBigNum::pos(U256::from(3u64)));
        assert_eq!(tree.get(3), SignedBigNum::pos(U256::from(4u64)));
        assert_eq!(tree.get(4), SignedBigNum::pos(U256::from(0u64)));
    }

    #[test]
    fn test_ancestor_at() {
        let mut tree = MinLinkCutTree::new();
        tree.make_tree(0);
        tree.make_tree(1);
        tree.make_tree(2);
        tree.make_tree(3);
        tree.make_tree(4);
        tree.make_tree(5);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);
        tree.link(3, 5);

        assert_eq!(tree.ancestor_at(4, 0), 0);
        assert_eq!(tree.ancestor_at(5, 1), 1);
        assert_eq!(tree.ancestor_at(5, 2), 3);
        assert_eq!(tree.ancestor_at(3, 1), 1);
        assert_eq!(tree.ancestor_at(4, 1), 4);
    }

    #[test]
    fn test_catepillar_apply() {
        let mut tree = MinLinkCutTree::new();
        tree.make_tree(5);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);
        tree.link(3, 5);

        tree.catepillar_apply(3, &SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.get(0), SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.get(1), SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.get(2), SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.get(3), SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.get(4), SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.get(5), SignedBigNum::pos(U256::from(1)));

        tree.catepillar_apply(2, &SignedBigNum::pos(U256::from(2)));
        assert_eq!(tree.get(0), SignedBigNum::pos(U256::from(3)));
        assert_eq!(tree.get(1), SignedBigNum::pos(U256::from(3)));
        assert_eq!(tree.get(2), SignedBigNum::pos(U256::from(3)));
        assert_eq!(tree.get(3), SignedBigNum::pos(U256::from(3)));
        assert_eq!(tree.get(4), SignedBigNum::pos(U256::from(3)));
        assert_eq!(tree.get(5), SignedBigNum::pos(U256::from(1)));

        tree.path_apply(1, &SignedBigNum::pos(U256::from(1)));
        assert_eq!(tree.path_aggregate(2), SignedBigNum::pos(U256::from(3)));
        assert_eq!(tree.path_aggregate_idx(2), 2);
        tree.path_apply(0, &SignedBigNum::neg(U256::from(2)));
        assert_eq!(tree.path_aggregate(2), SignedBigNum::pos(U256::from(2)));
        assert_eq!(tree.path_aggregate_idx(2), 0);
    }
}
