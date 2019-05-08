// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::U256;
use std::{
    cmp::{min, Ordering},
    convert, ops,
};

const NULL: usize = !0;

#[derive(Copy, Clone, Eq, Debug)]
pub struct SignedBigNum {
    sign: bool,
    num: U256,
}

impl SignedBigNum {
    fn zero() -> Self {
        Self {
            sign: false,
            num: U256::zero(),
        }
    }

    pub fn neg(num: U256) -> Self { Self { sign: true, num } }

    pub fn pos(num: U256) -> Self { Self { sign: false, num } }
}

impl convert::From<U256> for SignedBigNum {
    fn from(num: U256) -> Self { Self { sign: false, num } }
}

impl convert::From<SignedBigNum> for U256 {
    fn from(signed_num: SignedBigNum) -> Self {
        assert!(!signed_num.sign);
        signed_num.num
    }
}

impl ops::Add<SignedBigNum> for SignedBigNum {
    type Output = SignedBigNum;

    fn add(self, other: SignedBigNum) -> SignedBigNum {
        if self.sign == other.sign {
            SignedBigNum {
                sign: self.sign,
                num: self.num + other.num,
            }
        } else if self.num == other.num {
            SignedBigNum::zero()
        } else if self.num < other.num {
            SignedBigNum {
                sign: other.sign,
                num: other.num - self.num,
            }
        } else {
            SignedBigNum {
                sign: self.sign,
                num: self.num - other.num,
            }
        }
    }
}

impl ops::AddAssign<SignedBigNum> for SignedBigNum {
    fn add_assign(&mut self, other: SignedBigNum) {
        if self.sign == other.sign {
            self.num += other.num;
        } else if self.num == other.num {
            self.sign = false;
            self.num = U256::zero();
        } else if self.num < other.num {
            self.sign = other.sign;
            self.num = other.num - self.num;
        } else {
            self.num -= other.num;
        }
    }
}

impl Ord for SignedBigNum {
    fn cmp(&self, other: &SignedBigNum) -> Ordering {
        if self.sign != other.sign {
            return if self.sign {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        if self.num == other.num {
            return Ordering::Equal;
        }

        if self.sign {
            if self.num < other.num {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        } else {
            if self.num < other.num {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    }
}

impl PartialOrd for SignedBigNum {
    fn partial_cmp(&self, other: &SignedBigNum) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SignedBigNum {
    fn eq(&self, other: &SignedBigNum) -> bool {
        self.sign == other.sign && self.num == other.num
    }
}

#[derive(Clone)]
struct Node {
    left_child: usize,
    right_child: usize,
    parent: usize,
    path_parent: usize,
    size: usize,
    sum: SignedBigNum,
    delta: SignedBigNum,
}

impl Default for Node {
    fn default() -> Self {
        Node {
            left_child: NULL,
            right_child: NULL,
            parent: NULL,
            path_parent: NULL,
            size: 1,
            sum: SignedBigNum::zero(),
            delta: SignedBigNum::zero(),
        }
    }
}

pub struct LinkCutTree {
    tree: Vec<Node>,
}

impl LinkCutTree {
    pub fn new() -> Self { LinkCutTree { tree: Vec::new() } }

    pub fn make_tree(&mut self, v: usize) {
        if self.tree.len() <= v {
            self.tree.resize(v + 1, Node::default());
        }
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

        let sum =
            self.tree[v].sum + self.tree[v].delta + self.tree[parent].delta;
        self.tree[v].sum = sum;
        if self.tree[parent].left_child == v {
            let u = self.tree[v].right_child;
            let w = self.tree[v].left_child;
            self.tree[parent].size -= self.tree[v].size;
            self.tree[parent].left_child = u;
            if u != NULL {
                self.tree[u].parent = parent;
                self.tree[parent].size += self.tree[u].size;
                self.tree[v].size -= self.tree[u].size;
                let delta = self.tree[u].delta + self.tree[v].delta;
                self.tree[u].delta = delta;
            }
            if w != NULL {
                let delta = self.tree[w].delta
                    + self.tree[v].delta
                    + self.tree[parent].delta;
                self.tree[w].delta = delta;
            }
            self.tree[v].delta = SignedBigNum::zero();
            self.tree[v].right_child = parent;
            self.tree[parent].parent = v;
            self.tree[v].size += self.tree[parent].size;
        } else {
            let u = self.tree[v].left_child;
            let w = self.tree[v].right_child;
            self.tree[parent].size -= self.tree[v].size;
            self.tree[parent].right_child = u;
            if u != NULL {
                self.tree[u].parent = parent;
                self.tree[parent].size += self.tree[u].size;
                self.tree[v].size -= self.tree[u].size;
                let delta = self.tree[u].delta + self.tree[v].delta;
                self.tree[u].delta = delta;
            }
            if w != NULL {
                let delta = self.tree[w].delta
                    + self.tree[v].delta
                    + self.tree[parent].delta;
                self.tree[w].delta = delta;
            }
            self.tree[v].delta = SignedBigNum::zero();
            self.tree[v].left_child = parent;
            self.tree[parent].parent = v;
            self.tree[v].size += self.tree[parent].size;
        }
        self.tree[v].parent = grandparent;
        if grandparent != NULL {
            if self.tree[grandparent].left_child == parent {
                self.tree[grandparent].left_child = v;
            } else {
                self.tree[grandparent].right_child = v;
            }
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
            self.tree[u].path_parent = v;
            self.tree[u].parent = NULL;
            self.tree[v].right_child = NULL;
            self.tree[v].size -= self.tree[u].size;
        }
    }

    fn access(&mut self, v: usize) {
        if v == NULL {
            return;
        }

        self.splay(v);
        self.remove_preferred_child(v);

        while self.tree[v].path_parent != NULL {
            let w = self.tree[v].path_parent;
            self.splay(w);
            let u = self.tree[w].right_child;
            if u != NULL {
                self.tree[u].path_parent = w;
                self.tree[u].parent = NULL;
                self.tree[w].size -= self.tree[u].size;
            }
            self.tree[w].right_child = v;
            self.tree[v].parent = w;
            self.tree[w].size += self.tree[v].size;
            self.splay(v);
        }
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

        self.splay(w);
        self.remove_preferred_child(w);

        let mut x = w;
        let mut y = w;
        while self.tree[y].path_parent != NULL {
            let z = self.tree[y].path_parent;
            self.splay(z);
            if self.tree[z].path_parent == NULL {
                x = z;
            }
            let u = self.tree[z].right_child;
            if u != NULL {
                self.tree[u].path_parent = z;
                self.tree[u].parent = NULL;
                self.tree[z].size -= self.tree[u].size;
            }
            self.tree[z].right_child = y;
            self.tree[y].parent = z;
            self.tree[z].size += self.tree[y].size;
            self.tree[y].path_parent = NULL;
            y = z;
        }
        self.splay(w);

        x
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

    pub fn update_weight(&mut self, v: usize, weight: &SignedBigNum) {
        self.access(v);

        self.tree[v].sum += *weight;
        let u = self.tree[v].left_child;
        if u != NULL {
            self.tree[u].delta += *weight;
        }
    }

    pub fn subtree_weight(&mut self, v: usize) -> U256 {
        self.access(v);
        U256::from(self.tree[v].sum.clone())
    }
}

#[derive(Clone)]
struct MinNode {
    left_child: usize,
    right_child: usize,
    parent: usize,
    path_parent: usize,
    size: usize,
    value: SignedBigNum,
    min: SignedBigNum,
    delta: SignedBigNum,
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
            delta: SignedBigNum::zero(),
        }
    }
}

pub struct MinLinkCutTree {
    tree: Vec<MinNode>,
}

impl MinLinkCutTree {
    pub fn new() -> Self { Self { tree: Vec::new() } }

    pub fn make_tree(&mut self, v: usize) {
        if self.tree.len() <= v {
            self.tree.resize(v + 1, MinNode::default());
        }
    }

    fn update(&mut self, v: usize) {
        self.tree[v].size = 1;
        self.tree[v].min = self.tree[v].value;

        let u = self.tree[v].left_child;
        if u != NULL {
            self.tree[v].size += self.tree[u].size;
            self.tree[v].min = min(self.tree[v].min, self.tree[u].min);
        }
        let w = self.tree[v].right_child;
        if w != NULL {
            self.tree[v].size += self.tree[w].size;
            self.tree[v].min = min(self.tree[v].min, self.tree[w].min);
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

        if self.tree[parent].left_child == v {
            let u = self.tree[v].right_child;
            let w = self.tree[v].left_child;
            self.tree[parent].left_child = u;
            if u != NULL {
                self.tree[u].parent = parent;
                self.tree[u].delta = self.tree[u].delta + self.tree[v].delta;
                self.update(u);
            }
            if w != NULL {
                self.tree[w].delta = self.tree[w].delta
                    + self.tree[v].delta
                    + self.tree[parent].delta;
                self.update(w);
            }
            self.tree[v].value = self.tree[v].value + self.tree[v].delta;
            self.tree[v].delta = SignedBigNum::zero();
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
                self.update(u);
            }
            if w != NULL {
                self.tree[w].delta = self.tree[w].delta
                    + self.tree[v].delta
                    + self.tree[parent].delta;
                self.update(w);
            }
            self.tree[v].value = self.tree[v].value + self.tree[v].delta;
            self.tree[v].delta = SignedBigNum::zero();
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
            self.tree[u].path_parent = v;
            self.tree[u].parent = NULL;
            self.tree[v].right_child = NULL;
            self.tree[v].size -= self.tree[u].size;
        }
    }

    fn access(&mut self, v: usize) {
        if v == NULL {
            return;
        }

        self.splay(v);
        self.remove_preferred_child(v);
        self.update(v);

        while self.tree[v].path_parent != NULL {
            let w = self.tree[v].path_parent;
            self.splay(w);
            let u = self.tree[w].right_child;
            if u != NULL {
                self.tree[u].path_parent = w;
                self.tree[u].parent = NULL;
            }
            self.tree[w].right_child = v;
            self.tree[v].parent = w;
            self.update(w);
            self.splay(v);
        }
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

        self.splay(w);
        self.remove_preferred_child(w);

        let mut x = w;
        let mut y = w;
        while self.tree[y].path_parent != NULL {
            let z = self.tree[y].path_parent;
            self.splay(z);
            if self.tree[z].path_parent == NULL {
                x = z;
            }
            let u = self.tree[z].right_child;
            if u != NULL {
                self.tree[u].path_parent = z;
                self.tree[u].parent = NULL;
                self.tree[z].size -= self.tree[u].size;
            }
            self.tree[z].right_child = y;
            self.tree[y].parent = z;
            self.tree[z].size += self.tree[y].size;
            self.tree[y].path_parent = NULL;
            y = z;
        }
        self.splay(w);

        x
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

    pub fn set(&mut self, v: usize, value: &U256) {
        self.access(v);

        self.tree[v].value = SignedBigNum::pos(*value);
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

    pub fn path_aggregate(&mut self, v: usize) -> SignedBigNum {
        self.access(v);
        self.update(v);

        self.tree[v].min.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkCutTree, MinLinkCutTree, U256};
    use crate::SignedBigNum;

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

        tree.set(0, &U256::from(10));
        tree.set(1, &U256::from(9));
        tree.set(2, &U256::from(8));
        tree.set(3, &U256::from(7));
        tree.set(4, &U256::from(6));

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
        let mut tree = LinkCutTree::new();

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
    fn test_subtree_weight() {
        let mut tree = LinkCutTree::new();
        tree.make_tree(0);
        tree.make_tree(1);
        tree.make_tree(2);
        tree.make_tree(3);
        tree.make_tree(4);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);
        tree.update_weight(0, &SignedBigNum::pos(U256::from(1u64)));
        tree.update_weight(1, &SignedBigNum::pos(U256::from(2u64)));
        tree.update_weight(2, &SignedBigNum::pos(U256::from(3u64)));
        tree.update_weight(3, &SignedBigNum::pos(U256::from(4u64)));
        tree.update_weight(4, &SignedBigNum::pos(U256::from(5u64)));

        assert_eq!(tree.subtree_weight(0), U256::from(15u64));
        assert_eq!(tree.subtree_weight(1), U256::from(9u64));
        assert_eq!(tree.subtree_weight(2), U256::from(3u64));
        assert_eq!(tree.subtree_weight(3), U256::from(4u64));
        assert_eq!(tree.subtree_weight(4), U256::from(5u64));

        tree.update_weight(4, &SignedBigNum::neg(U256::from(5u64)));
        assert_eq!(tree.subtree_weight(0), U256::from(10u64));
        assert_eq!(tree.subtree_weight(1), U256::from(9u64));
        assert_eq!(tree.subtree_weight(2), U256::from(3u64));
        assert_eq!(tree.subtree_weight(3), U256::from(4u64));
        assert_eq!(tree.subtree_weight(4), U256::from(0u64));
    }

    #[test]
    fn test_ancestor_at() {
        let mut tree = LinkCutTree::new();
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
}
