// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::Mutex;

mod lct;

use lct::{
    Caterpillar, DeltaAndPreferredChild, Link, LinkCutTree, PathLength, Unit,
    Update,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};

pub struct MutexLinkCutTree<Ext> {
    inner: Mutex<LinkCutTree<Ext>>,
}

impl<Ext> MallocSizeOf for MutexLinkCutTree<Ext> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.inner.lock().size_of(ops)
    }
}

impl<Ext: Update + DeltaAndPreferredChild + Link + Clone + Default>
    MutexLinkCutTree<Ext>
{
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LinkCutTree::<Ext>::new()),
        }
    }

    pub fn size(&self) -> usize { self.inner.lock().size() }

    pub fn make_tree(&mut self, v: usize) { self.inner.lock().make_tree(v); }

    pub fn link(&mut self, v: usize, w: usize) { self.inner.lock().link(v, w); }

    pub fn lca(&self, v: usize, w: usize) -> usize {
        self.inner.lock().lca(v, w)
    }

    pub fn set(&mut self, v: usize, value: i128) {
        self.inner.lock().set(v, value);
    }

    pub fn path_apply(&mut self, v: usize, delta: i128) {
        self.inner.lock().path_apply(v, delta);
    }

    pub fn path_aggregate(&self, v: usize) -> i128 {
        self.inner.lock().path_aggregate(v)
    }

    pub fn path_aggregate_chop(&mut self, v: usize, u: usize) -> i128 {
        self.inner.lock().path_aggregate_chop(v, u)
    }

    pub fn split_root(&mut self, parent: usize, v: usize) {
        self.inner.lock().split_root(parent, v);
    }

    pub fn get(&self, v: usize) -> i128 { self.inner.lock().get(v) }
}

impl MutexLinkCutTree<Caterpillar> {
    pub fn caterpillar_apply(&mut self, v: usize, caterpillar_delta: i128) {
        self.inner.lock().caterpillar_apply(v, caterpillar_delta);
    }
}

impl MutexLinkCutTree<PathLength> {
    pub fn ancestor_at(&self, v: usize, at: usize) -> usize {
        self.inner.lock().ancestor_at(v, at)
    }
}

/// default implementation of link cut tree, ancestor_at and caterpillar_apply
/// not supported
pub type DefaultMinLinkCutTree = MutexLinkCutTree<Unit>;
/// link cut tree with support for ancestor_at
pub type SizeMinLinkCutTree = MutexLinkCutTree<PathLength>;
/// link cut tree with support for caterpillar_apply
pub type CaterpillarMinLinkCutTree = MutexLinkCutTree<Caterpillar>;

#[cfg(test)]
mod tests {
    use super::{
        CaterpillarMinLinkCutTree, DefaultMinLinkCutTree,
        DeltaAndPreferredChild, Link, MutexLinkCutTree, SizeMinLinkCutTree,
        Update,
    };
    use crate::lct::NULL;
    use rand::Rng;

    trait TestExt:
        Update + DeltaAndPreferredChild + Link + Clone + Default
    {
    }
    impl<Ext: Update + DeltaAndPreferredChild + Link + Clone + Default> TestExt
        for Ext
    {
    }

    fn test_min<Ext: TestExt>(mut tree: MutexLinkCutTree<Ext>) {
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

        tree.set(0, 10);
        tree.set(1, 9);
        tree.set(2, 8);
        tree.set(3, 7);
        tree.set(4, 6);

        assert_eq!(tree.path_aggregate(0), 10);
        assert_eq!(tree.path_aggregate(1), 9);
        assert_eq!(tree.path_aggregate(2), 8);
        assert_eq!(tree.path_aggregate(3), 7);
        assert_eq!(tree.path_aggregate(4), 6);

        tree.path_apply(1, -5);

        assert_eq!(tree.path_aggregate(0), 5);
        assert_eq!(tree.path_aggregate(1), 4);
        assert_eq!(tree.path_aggregate(2), 4);
        assert_eq!(tree.path_aggregate(3), 4);
        assert_eq!(tree.path_aggregate(4), 5);
    }

    fn test_lca<Ext: TestExt>(mut tree: MutexLinkCutTree<Ext>) {
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

    fn test_get<Ext: TestExt>(mut tree: MutexLinkCutTree<Ext>) {
        tree.make_tree(0);
        tree.make_tree(1);
        tree.make_tree(2);
        tree.make_tree(3);
        tree.make_tree(4);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);
        tree.path_apply(0, 1);
        tree.path_apply(1, 2);
        tree.path_apply(2, 3);
        tree.path_apply(3, 4);
        tree.path_apply(4, 5);

        assert_eq!(tree.get(0), 15);
        assert_eq!(tree.get(1), 9);
        assert_eq!(tree.get(2), 3);
        assert_eq!(tree.get(3), 4);
        assert_eq!(tree.get(4), 5);

        tree.path_apply(4, -5);
        assert_eq!(tree.get(0), 10);
        assert_eq!(tree.get(1), 9);
        assert_eq!(tree.get(2), 3);
        assert_eq!(tree.get(3), 4);
        assert_eq!(tree.get(4), 0);
    }

    #[test]
    fn test_min_default() { test_min(DefaultMinLinkCutTree::new()) }

    #[test]
    fn test_min_size() { test_min(SizeMinLinkCutTree::new()) }

    #[test]
    fn test_min_caterpillar() { test_min(CaterpillarMinLinkCutTree::new()) }

    #[test]
    fn test_lca_default() { test_lca(DefaultMinLinkCutTree::new()) }

    #[test]
    fn test_lca_size() { test_lca(SizeMinLinkCutTree::new()) }

    #[test]
    fn test_lca_caterpillar() { test_lca(CaterpillarMinLinkCutTree::new()) }

    #[test]
    fn test_get_default() { test_get(DefaultMinLinkCutTree::new()) }

    #[test]
    fn test_get_size() { test_get(SizeMinLinkCutTree::new()) }

    #[test]
    fn test_get_caterpillar() { test_get(CaterpillarMinLinkCutTree::new()) }

    #[test]
    fn test_ancestor_at() {
        let mut tree: SizeMinLinkCutTree = SizeMinLinkCutTree::new();
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
    fn test_caterpillar_apply() {
        let mut tree: CaterpillarMinLinkCutTree =
            CaterpillarMinLinkCutTree::new();
        tree.make_tree(5);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);
        tree.link(3, 5);

        tree.caterpillar_apply(3, 1);
        assert_eq!(tree.get(0), 1);
        assert_eq!(tree.get(1), 1);
        assert_eq!(tree.get(2), 1);
        assert_eq!(tree.get(3), 1);
        assert_eq!(tree.get(4), 1);
        assert_eq!(tree.get(5), 1);

        tree.caterpillar_apply(2, 2);
        assert_eq!(tree.get(0), 3);
        assert_eq!(tree.get(1), 3);
        assert_eq!(tree.get(2), 3);
        assert_eq!(tree.get(3), 3);
        assert_eq!(tree.get(4), 3);
        assert_eq!(tree.get(5), 1);

        tree.path_apply(1, 1);
        assert_eq!(tree.path_aggregate(2), 3);
        //        assert_eq!(tree.path_aggregate_idx(2), 2);
        tree.path_apply(0, -2);
        assert_eq!(tree.path_aggregate(2), 2);
        //        assert_eq!(tree.path_aggregate_idx(2), 0);
    }

    #[test]
    fn test_link_and_split_root() {
        let mut tree: CaterpillarMinLinkCutTree =
            CaterpillarMinLinkCutTree::new();
        tree.make_tree(5);
        tree.link(0, 1);
        tree.link(1, 2);
        tree.link(1, 3);
        tree.link(0, 4);

        tree.caterpillar_apply(3, 1);

        assert_eq!(tree.get(0), 1);
        assert_eq!(tree.get(1), 1);
        assert_eq!(tree.get(2), 1);
        assert_eq!(tree.get(3), 1);
        assert_eq!(tree.get(4), 1);
        assert_eq!(tree.get(5), 0);

        tree.link(3, 5);

        assert_eq!(tree.get(0), 1);
        assert_eq!(tree.get(1), 1);
        assert_eq!(tree.get(2), 1);
        assert_eq!(tree.get(3), 1);
        assert_eq!(tree.get(4), 1);
        assert_eq!(tree.get(5), 0);

        tree.caterpillar_apply(2, 2);
        assert_eq!(tree.get(0), 3);
        assert_eq!(tree.get(1), 3);
        assert_eq!(tree.get(2), 3);
        assert_eq!(tree.get(3), 3);
        assert_eq!(tree.get(4), 3);
        assert_eq!(tree.get(5), 0);

        tree.split_root(1, 3);

        assert_eq!(tree.get(0), 3);
        assert_eq!(tree.get(1), 3);
        assert_eq!(tree.get(2), 3);
        assert_eq!(tree.get(3), 3);
        assert_eq!(tree.get(4), 3);
        assert_eq!(tree.get(5), 0);
    }

    fn path_apply_brutal(
        parent: &Vec<usize>, value: &mut Vec<i64>, u: usize, v: i64,
    ) {
        let mut p = u;
        while p != NULL {
            value[p] += v;
            p = parent[p];
        }
    }

    fn caterpillar_apply_brutal(
        parent: &Vec<usize>, value: &mut Vec<i64>, u: usize, v: i64,
    ) {
        let mut mark: Vec<bool> = Vec::new();
        mark.resize(parent.len(), false);
        let mut p = u;
        let mut root = u;
        while p != NULL {
            mark[p] = true;
            root = p;
            p = parent[p];
        }
        for i in 0..parent.len() {
            if (parent[i] != NULL || i == root) && (mark[i] || mark[parent[i]])
            {
                value[i] += v;
            }
        }
    }

    fn query_min_brutal(
        parent: &Vec<usize>, value: &Vec<i64>, u: usize,
    ) -> i64 {
        let mut v = value[u];
        let mut p = u;
        while p != NULL {
            v = std::cmp::min(v, value[p]);
            p = parent[p];
        }

        v
    }

    fn lca_brutal(parent: &Vec<usize>, u: usize, v: usize) -> usize {
        let mut mark: Vec<bool> = Vec::new();
        mark.resize(parent.len(), false);
        let mut p = u;
        while p != NULL {
            mark[p] = true;
            p = parent[p];
        }
        let mut p = v;
        while p != NULL {
            if mark[p] {
                return p;
            }
            p = parent[p];
        }
        NULL
    }

    fn ancestor_at_brutal(parent: &Vec<usize>, u: usize, at: usize) -> usize {
        let mut path = Vec::new();
        let mut p = u;
        while p != NULL {
            path.push(p);
            p = parent[p];
        }
        path.reverse();
        if at >= path.len() {
            NULL
        } else {
            path[at]
        }
    }

    fn get_root(dsu: &mut Vec<usize>, x: usize) -> usize {
        if dsu[x] != NULL {
            dsu[x] = get_root(dsu, dsu[x]);
            dsu[x]
        } else {
            x
        }
    }

    #[test]
    fn test_default_random_stress() {
        let bound: i64 = 100_000_000;
        let mut n: usize = 5000;
        let mut parent: Vec<usize> = Vec::new();
        let mut value: Vec<i64> = Vec::new();
        parent.push(NULL);
        for i in 1..n {
            let p: usize = rand::thread_rng().gen_range(0, i) as usize;
            parent.push(p);
        }
        value.resize(n, 0);
        let mut tree: DefaultMinLinkCutTree = DefaultMinLinkCutTree::new();
        tree.make_tree(n - 1);
        for i in 1..n {
            tree.link(parent[i], i);
        }
        assert_eq!(tree.size(), n);
        for _ in 0..80000 {
            let op: u32 = rand::thread_rng().gen_range(0, 7);
            if op == 0 {
                // path apply
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.path_apply(u as usize, v as i128);
                path_apply_brutal(&parent, &mut value, u, v);
            } else if op == 1 {
                // query min
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(
                    query_min_brutal(&parent, &value, u),
                    tree.path_aggregate(u) as i64
                );
            } else if op == 2 {
                // lca
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(lca_brutal(&parent, u, v), tree.lca(u, v));
            } else if op == 3 {
                // query chop
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let mut p = u;
                let mut v = value[p];
                while p != NULL {
                    if p != u {
                        assert_eq!(v, tree.path_aggregate_chop(u, p) as i64);
                    }
                    v = std::cmp::min(v, value[p]);
                    p = parent[p];
                }
            } else if op == 4 {
                // set
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.set(u, v as i128);
                value[u] = v;
            } else if op == 5 {
                // get
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(value[u], tree.get(u) as i64);
            } else if op == 6 {
                let p: usize = rand::thread_rng().gen_range(0, n) as usize;
                parent.push(p);
                value.push(0);
                tree.make_tree(n);
                tree.link(p, n);
                n += 1;
            }
        }
    }

    #[test]
    fn test_size_random_stress() {
        let bound: i64 = 100_000_000;
        let mut n: usize = 5000;
        let mut parent: Vec<usize> = Vec::new();
        let mut value: Vec<i64> = Vec::new();
        parent.push(NULL);
        for i in 1..n {
            let p: usize = rand::thread_rng().gen_range(0, i) as usize;
            parent.push(p);
        }
        value.resize(n, 0);
        let mut tree: SizeMinLinkCutTree = SizeMinLinkCutTree::new();
        tree.make_tree(n - 1);
        for i in 1..n {
            tree.link(parent[i], i);
        }
        assert_eq!(tree.size(), n);
        for _ in 0..80000 {
            let op: u32 = rand::thread_rng().gen_range(0, 8);
            if op == 0 {
                // path apply
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.path_apply(u as usize, v as i128);
                path_apply_brutal(&parent, &mut value, u, v);
            } else if op == 1 {
                // query min
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(
                    query_min_brutal(&parent, &value, u),
                    tree.path_aggregate(u) as i64
                );
            } else if op == 2 {
                // lca
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(lca_brutal(&parent, u, v), tree.lca(u, v));
            } else if op == 3 {
                // query chop
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let mut p = u;
                let mut v = value[p];
                while p != NULL {
                    if p != u {
                        assert_eq!(v, tree.path_aggregate_chop(u, p) as i64);
                    }
                    v = std::cmp::min(v, value[p]);
                    p = parent[p];
                }
            } else if op == 4 {
                // set
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.set(u, v as i128);
                value[u] = v;
            } else if op == 5 {
                // ancestor at
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let at: usize = rand::thread_rng().gen_range(0, 100) as usize;
                assert_eq!(
                    ancestor_at_brutal(&parent, u, at),
                    tree.ancestor_at(u as usize, at)
                );
            } else if op == 6 {
                // get
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(value[u], tree.get(u) as i64);
            } else if op == 7 {
                let p: usize = rand::thread_rng().gen_range(0, n) as usize;
                parent.push(p);
                value.push(0);
                tree.make_tree(n);
                tree.link(p, n);
                n += 1;
            }
        }
    }

    #[test]
    fn test_caterpillar_random_stress() {
        let bound: i64 = 1_000_000;
        let mut n: usize = 5000;
        let mut parent: Vec<usize> = Vec::new();
        let mut value: Vec<i64> = Vec::new();
        parent.push(NULL);
        for i in 1..n {
            let p: usize = rand::thread_rng().gen_range(0, i) as usize;
            parent.push(p);
        }
        value.resize(n, 0);
        let mut tree: CaterpillarMinLinkCutTree =
            CaterpillarMinLinkCutTree::new();
        tree.make_tree(n - 1);
        for i in 1..n {
            tree.link(parent[i], i);
        }
        assert_eq!(tree.size(), n);
        for _ in 0..80000 {
            let op: u32 = rand::thread_rng().gen_range(0, 9);
            if op == 0 {
                // path apply
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.path_apply(u as usize, v as i128);
                path_apply_brutal(&parent, &mut value, u, v);
            } else if op == 1 {
                // caterpillar apply
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.caterpillar_apply(u, v as i128);
                caterpillar_apply_brutal(&parent, &mut value, u, v);
            } else if op == 2 {
                // query min
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(
                    query_min_brutal(&parent, &value, u),
                    tree.path_aggregate(u) as i64
                );
            } else if op == 3 {
                // query chop
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let mut p = u;
                let mut v = value[p];
                while p != NULL {
                    if p != u {
                        assert_eq!(v, tree.path_aggregate_chop(u, p) as i64);
                    }
                    v = std::cmp::min(v, value[p]);
                    p = parent[p];
                }
            } else if op == 4 {
                // set
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                let v: i64 = rand::thread_rng().gen_range(-bound, bound);
                tree.set(u, v as i128);
                value[u] = v;
            } else if op == 5 {
                // get
                let u: usize = rand::thread_rng().gen_range(0, n) as usize;
                assert_eq!(value[u], tree.get(u) as i64);
            } else if op == 6 {
                // make tree
                let p: usize = rand::thread_rng().gen_range(0, n) as usize;
                parent.push(p);
                value.push(0);
                tree.make_tree(n);
                tree.link(p, n);
                n += 1;
            } else if op == 7 {
                // split root
                let i: usize = rand::thread_rng().gen_range(0, n) as usize;
                if parent[i] != NULL {
                    tree.split_root(parent[i], i);
                    parent[i] = NULL;
                }
            } else if op == 8 {
                // link
                let mut dsu = parent.clone();
                let mut null_vec = Vec::new();
                for i in 0..n {
                    if get_root(&mut dsu, i) == i {
                        null_vec.push(i);
                    }
                }
                if null_vec.len() != 1 {
                    let i: usize = rand::thread_rng()
                        .gen_range(0, null_vec.len())
                        as usize;
                    let i = null_vec[i];
                    let mut can = Vec::new();
                    for v in 0..n {
                        if get_root(&mut dsu, v) != i {
                            can.push(v);
                        }
                    }
                    let p: usize =
                        rand::thread_rng().gen_range(0, can.len()) as usize;
                    let p = can[p];
                    tree.link(p, i);
                    parent[i] = p;
                }
            }
        }
    }
}
