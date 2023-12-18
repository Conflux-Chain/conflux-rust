// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use std::{
    cmp::Ordering,
    mem,
    ops::{Add, Sub},
};

pub struct Node<K, V, W> {
    pub key: K,
    pub value: V,
    weight: W,
    sum_weight: W,
    priority: u64,
    pub left: Option<Box<Node<K, V, W>>>,
    pub right: Option<Box<Node<K, V, W>>>,
}

impl<K: MallocSizeOf, V: MallocSizeOf, W: MallocSizeOf> MallocSizeOf
    for Node<K, V, W>
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.key.size_of(ops)
            + self.value.size_of(ops)
            + self.weight.size_of(ops)
            + self.sum_weight.size_of(ops)
            + self.left.size_of(ops)
            + self.right.size_of(ops)
    }
}

impl<K: Ord, V: Clone, W: Add<Output = W> + Sub<Output = W> + Ord + Clone>
    Node<K, V, W>
{
    pub fn new(key: K, value: V, weight: W, priority: u64) -> Node<K, V, W> {
        Node {
            key,
            value,
            sum_weight: weight.clone(),
            weight,
            priority,
            left: None,
            right: None,
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        match key.cmp(&self.key) {
            Ordering::Equal => Some(&self.value),
            Ordering::Less => self.left.as_ref().and_then(|x| x.get(key)),
            Ordering::Greater => self.right.as_ref().and_then(|x| x.get(key)),
        }
    }

    pub fn insert(
        node: &mut Option<Box<Node<K, V, W>>>, new: Node<K, V, W>,
    ) -> Option<V> {
        let node = if let Some(node) = node {
            node
        } else {
            *node = Some(Box::new(new));
            return None;
        };
        match new.key.cmp(&node.key) {
            Ordering::Equal => {
                let result = Some(node.value.clone());
                node.value = new.value;
                node.weight = new.weight;
                node.update_weight();
                result
            }
            Ordering::Less => {
                let result = Node::insert(&mut node.left, new);
                if node.priority < node.left.as_ref().unwrap().priority {
                    Node::right_rotate(node);
                }
                node.update_weight();
                result
            }
            Ordering::Greater => {
                let result = Node::insert(&mut node.right, new);
                if node.priority < node.right.as_ref().unwrap().priority {
                    Node::left_rotate(node);
                }
                node.update_weight();
                result
            }
        }
    }

    pub fn remove(
        maybe_node: &mut Option<Box<Node<K, V, W>>>, key: &K,
    ) -> Option<V> {
        let node = maybe_node.as_mut()?;
        let result = match key.cmp(&node.key) {
            Ordering::Equal => {
                let rot_left;
                match (&node.left, &node.right) {
                    (None, None) => {
                        // Both is None, remove current node directly
                        return Some(
                            mem::replace(maybe_node, None).unwrap().value,
                        );
                    }
                    (None, Some(_)) => {
                        rot_left = true;
                    }
                    (Some(_), None) => {
                        rot_left = false;
                    }
                    (Some(left), Some(right)) => {
                        rot_left = left.priority < right.priority;
                    }
                }

                match rot_left {
                    true => {
                        // rot left
                        Node::left_rotate(node);
                        Node::remove(&mut node.left, key)
                    }
                    false => {
                        // rot right
                        Node::right_rotate(node);
                        Node::remove(&mut node.right, key)
                    }
                }
            }
            Ordering::Less => Node::remove(&mut node.left, key),
            Ordering::Greater => Node::remove(&mut node.right, key),
        };
        node.update_weight();
        result
    }

    pub fn get_by_weight(&self, weight: W) -> Option<&V> {
        let mut pre_weight = self.weight.clone();
        if let Some(ref left) = self.left {
            if &weight < &left.sum_weight {
                return left.get_by_weight(weight);
            } else {
                pre_weight = pre_weight + left.sum_weight.clone();
            }
        }
        if &weight < &pre_weight {
            return Some(&self.value);
        }
        self.right
            .as_ref()
            .and_then(|x| x.get_by_weight(weight - pre_weight))
    }

    fn right_rotate(node: &mut Box<Node<K, V, W>>) {
        let new = mem::replace(&mut node.left, None);
        if let Some(mut new) = new {
            mem::swap(node, &mut new);
            mem::swap(&mut node.right, &mut new.left);
            new.update_weight();
            node.right = Some(new);
            node.update_weight();
        }
    }

    fn left_rotate(node: &mut Box<Node<K, V, W>>) {
        let new = mem::replace(&mut node.right, None);
        if let Some(mut new) = new {
            mem::swap(node, &mut new);
            mem::swap(&mut node.left, &mut new.right);
            new.update_weight();
            node.left = Some(new);
            node.update_weight();
        }
    }

    fn update_weight(&mut self) {
        self.sum_weight = self.weight.clone();
        if let Some(left) = &self.left {
            self.sum_weight = self.sum_weight.clone() + left.sum_weight.clone();
        }
        if let Some(right) = &self.right {
            self.sum_weight =
                self.sum_weight.clone() + right.sum_weight.clone();
        }
    }

    pub fn sum_weight(&self) -> W { self.sum_weight.clone() }
}
