use super::*;

impl<K: hash::Hash + Eq + Copy + Debug, V: Eq + Ord + Clone> Clone
    for HeapMap<K, V>
{
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            mapping: self.mapping.clone(),
        }
    }
}

impl<K: hash::Hash + Eq + Copy + Debug, V: Eq + Ord + Clone> HeapMap<K, V> {
    fn check_mono(&self) -> bool {
        let mut me = self.clone();
        let mut last_value = if let Some((_k, v)) = me.pop() {
            v
        } else {
            return true;
        };

        while let Some((_k, v)) = me.pop() {
            if v > last_value {
                return false;
            }
            last_value = v;
        }

        true
    }
}

#[test]
fn test_simple() {
    let mut map = HeapMap::<usize, usize>::new();
    map.insert(&1, 1);
    map.insert(&2, 2);
    assert_eq!(Some((2, 2)), map.pop());
    assert_eq!(Some((1, 1)), map.pop());
    assert_eq!(None, map.pop());
}

#[test]
fn test_random() {
    const SIZE: usize = 10000usize;
    let key = || rand::random::<usize>() % (SIZE * 2);
    let mut map = HeapMap::<usize, usize>::new();

    for _round in 0..10 {
        for _ in 0..SIZE {
            map.insert(&key(), rand::random());
        }
        for _iter in 0..1000 {
            map.remove(&key());
            map.insert(&key(), rand::random());
            if _iter % 10 == 9 {
                assert!(map.check_mono());
            }
        }
    }
}
