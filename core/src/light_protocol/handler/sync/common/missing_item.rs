// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{cmp::Ordering, time::Instant};

pub trait HasKey<Key>
where
    Key: Clone,
{
    fn key(&self) -> Key;
}

/// Items whose priority is based on their creation times.
/// I.e. items created earlier will have higher priority.
/// Example: TimeOrdered(yesterday) > TimeOrdered(now)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeOrdered<K> {
    pub key: K,
    pub since: Instant,
}

impl<K> TimeOrdered<K> {
    pub fn new(key: K) -> Self {
        TimeOrdered {
            key,
            since: Instant::now(),
        }
    }
}

impl<K> HasKey<K> for TimeOrdered<K>
where
    K: Clone,
{
    fn key(&self) -> K {
        self.key.clone()
    }
}

impl<K> Ord for TimeOrdered<K>
where
    K: Eq,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.since.cmp(&other.since).reverse()
    }
}

impl<K> PartialOrd for TimeOrdered<K>
where
    K: Eq,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Items whose priority corresponds to their keys' priority.
/// I.e. items with higher key will have higher priority.
/// Example: KeyOrdered(3) > KeyOrdered(2)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyOrdered<K> {
    pub key: K,
    pub since: Instant,
}

impl<K> KeyOrdered<K> {
    pub fn new(key: K) -> Self {
        KeyOrdered {
            key,
            since: Instant::now(),
        }
    }
}

impl<K> HasKey<K> for KeyOrdered<K>
where
    K: Clone,
{
    fn key(&self) -> K {
        self.key.clone()
    }
}

impl<K> Ord for KeyOrdered<K>
where
    K: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl<K> PartialOrd for KeyOrdered<K>
where
    K: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Items whose priority is the reverse of their keys' priority.
/// I.e. items with lower key will have higher priority.
/// Example: KeyReverseOrdered(2) > KeyReverseOrdered(3)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyReverseOrdered<K> {
    pub key: K,
    pub since: Instant,
}

impl<K> KeyReverseOrdered<K> {
    pub fn new(key: K) -> Self {
        KeyReverseOrdered {
            key,
            since: Instant::now(),
        }
    }
}

impl<K> HasKey<K> for KeyReverseOrdered<K>
where
    K: Clone,
{
    fn key(&self) -> K {
        self.key.clone()
    }
}

impl<K> Ord for KeyReverseOrdered<K>
where
    K: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key).reverse()
    }
}

impl<K> PartialOrd for KeyReverseOrdered<K>
where
    K: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
