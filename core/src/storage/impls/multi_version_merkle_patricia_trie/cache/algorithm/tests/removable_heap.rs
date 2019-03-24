// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::{removable_heap::*, *},
    *,
};
use rand::Rng;
use std::{cmp::Ord, collections::HashSet, mem};

fn initialize_heap(
    capacity: u32, non_heap_size: u32,
) -> RemovableHeap<u32, TrivialValueWithHeapHandle<i64, u32>> {
    let mut rng = get_rng_for_test();
    let mut heap =
        RemovableHeap::<u32, TrivialValueWithHeapHandle<i64, u32>>::new(
            capacity,
        );
    let mut heap_util = TrivialHeapValueUtil::default();
    for i in 0..non_heap_size {
        let mut hole: Hole<TrivialValueWithHeapHandle<i64, u32>> =
            unsafe { mem::uninitialized() };
        hole.value = TrivialValueWithHeapHandle::<i64, u32>::new(
            rng.gen_range(-100, -1),
        );
        unsafe {
            heap.hole_push_back_and_swap_unchecked(0, &mut hole, &mut heap_util)
        };
        hole.finalize(0, &mut heap_util);
    }

    // Save the sum in the last value.
    let mut sum = 0i64;
    for i in non_heap_size..capacity - 1 {
        let value = rng.gen_range(0, 1000000);
        sum += value;
        heap.insert(
            TrivialValueWithHeapHandle::<i64, u32>::new(value),
            &mut heap_util,
        )
        .unwrap();
    }

    heap.insert(
        TrivialValueWithHeapHandle::<i64, u32>::new(sum),
        &mut heap_util,
    )
    .unwrap();

    heap
}

fn check_and_sort_heap(
    heap: &mut RemovableHeap<u32, TrivialValueWithHeapHandle<i64, u32>>,
    capacity: u32, non_heap_size: u32,
)
{
    let mut heap_util = TrivialHeapValueUtil::default();
    for i in 0..capacity {
        assert_eq!(
            i,
            unsafe { heap.get_unchecked_mut(i) }
                .get_handle_mut()
                .get_pos()
        );
    }

    let value = heap.pop_head(&mut heap_util).unwrap();
    let mut sum = value.value;
    assert_eq!(true, value.value >= 0);
    for i in 1..capacity - non_heap_size - 1 {
        let new_value = heap.pop_head(&mut heap_util).unwrap();
        sum += new_value.value;
        assert_eq!(true, new_value >= value);
    }
    let expected_sum = heap.pop_head(&mut heap_util).unwrap().value;
    assert_eq!(expected_sum, sum);
}

#[test]
fn test_sort_with_heap_handle_check() {
    let mut heap = initialize_heap(50000u32, 0u32);
    check_and_sort_heap(&mut heap, 50000u32, 0u32);
    let mut heap = initialize_heap(50000u32, 1u32);
    check_and_sort_heap(&mut heap, 50000u32, 1u32);
    let mut heap = initialize_heap(50000u32, 100u32);
    check_and_sort_heap(&mut heap, 50000u32, 100u32);
}

struct ArrayPosHeapValueUtil<
    'a,
    HeapHandlePosT: PrimitiveNum,
    ValueType: Ord + Clone,
> {
    array: &'a mut [TrivialValueWithHeapHandle<ValueType, HeapHandlePosT>],
}

impl<'a, HeapHandlePosT: PrimitiveNum, ValueType: Ord + Clone>
    ArrayPosHeapValueUtil<'a, HeapHandlePosT, ValueType>
{
    fn new(
        array: &'a mut [TrivialValueWithHeapHandle<
            ValueType,
            HeapHandlePosT,
        >],
    ) -> Self
    {
        Self { array: array }
    }
}

impl<
        'a,
        HeapHandlePosT: PrimitiveNum,
        ValueType: Ord + Clone,
        PosT: PrimitiveNum,
    > HeapValueUtil<PosT, HeapHandlePosT>
    for ArrayPosHeapValueUtil<'a, HeapHandlePosT, ValueType>
{
    type KeyType = ValueType;

    fn set_handle(&mut self, value: &mut PosT, pos: HeapHandlePosT) {
        unsafe {
            self.array
                .get_unchecked_mut(MyInto::<usize>::into(*value))
                .set_handle(pos);
        }
    }

    fn set_handle_final(&mut self, value: &mut PosT, pos: HeapHandlePosT) {
        self.set_handle(value, pos);
    }

    fn set_removed(&mut self, value: &mut PosT) {
        unsafe {
            self.array
                .get_unchecked_mut(MyInto::<usize>::into(*value))
                .set_removed();
        }
    }

    fn get_key_for_comparison<'x>(&'x self, value: &'x PosT) -> &Self::KeyType {
        unsafe { self.array.get_unchecked(MyInto::<usize>::into(*value)) }
            .as_ref()
    }
}

fn initialize_heap_with_removals_and_updates(
    init_size: u32, removals: u32, mut insert_size: u32, kept_removals: u32,
    updates: u32,
) -> (
    RemovableHeap<u32, u32>,
    Vec<TrivialValueWithHeapHandle<i64, u32>>,
)
{
    let mut rng = get_rng_for_test();
    let mut values = vec![];
    let mut removal_indices = vec![];
    let mut kept_removal_indices = vec![];
    let mut update_indices = vec![];
    let update_ratio_inverse = 3;

    let mut sum = 0i64;
    for i in 0..init_size + insert_size {
        let value = rng.gen_range(0, 1000000);
        sum += value;
        values.push(TrivialValueWithHeapHandle::new(value));
    }

    {
        let mut removals_set = HashSet::new();
        for i in 0..kept_removals {
            loop {
                let pos = rng.gen_range::<usize>(0, init_size as usize);
                if removals_set.get(&pos).is_none() {
                    removals_set.insert(pos);
                    sum -= *values[pos].as_ref();
                    kept_removal_indices.push(pos);
                    break;
                }
            }
        }

        for i in 0..removals {
            loop {
                let pos = rng
                    .gen_range::<usize>(0, (init_size + insert_size) as usize);
                if removals_set.get(&pos).is_none() {
                    removals_set.insert(pos);
                    sum -= *values[pos].as_ref();
                    removal_indices.push(pos);
                    break;
                }
            }
        }

        for i in 0..updates {
            loop {
                let pos = rng
                    .gen_range::<usize>(0, (init_size + insert_size) as usize);
                if removals_set.get(&pos).is_none() {
                    removals_set.insert(pos);
                    sum -= *values[pos].as_ref();
                    sum += (*values[pos].as_ref()) / update_ratio_inverse;
                    update_indices.push(pos);
                    break;
                }
            }
        }
    }

    // Save the sum in the last value.
    values.push(TrivialValueWithHeapHandle::new(sum));
    insert_size += 1;

    let mut heap = RemovableHeap::<u32, u32>::new(init_size + insert_size);
    for i in 0..init_size {
        heap.insert(i, &mut ArrayPosHeapValueUtil::new(&mut values))
            .unwrap();
    }
    for i in 0..kept_removals {
        unsafe {
            heap.move_out_from_heap_at_unchecked(
                values[kept_removal_indices[i as usize]]
                    .get_handle_mut()
                    .get_pos(),
                &mut ArrayPosHeapValueUtil::new(&mut values),
            )
        };
    }
    for i in 0..insert_size {
        heap.insert(
            init_size + i,
            &mut ArrayPosHeapValueUtil::new(&mut values),
        )
        .unwrap();
    }
    for i in 0..removals {
        unsafe {
            heap.remove_at_unchecked(
                values[removal_indices[i as usize]]
                    .get_handle_mut()
                    .get_pos(),
                &mut ArrayPosHeapValueUtil::new(&mut values),
            )
        };
    }
    for i in 0..updates {
        let mut array_pos = update_indices[i as usize] as u32;
        let heap_pos = values[array_pos as usize].get_handle_mut().get_pos();
        values[array_pos as usize].value /= update_ratio_inverse;
        unsafe {
            heap.replace_at_unchecked(
                heap_pos,
                &mut array_pos,
                &mut ArrayPosHeapValueUtil::new(&mut values),
            )
        }
    }

    (heap, values)
}

fn check_and_sort_heap_array_pos(
    heap: &mut RemovableHeap<u32, u32>,
    values: &mut Vec<TrivialValueWithHeapHandle<i64, u32>>, size: u32,
    non_heap_size: u32,
)
{
    {
        let mut pos_set = HashSet::new();
        pos_set.insert(HeapHandle::default().get_pos());
        for i in 0..size {
            let pos = *unsafe { heap.get_unchecked_mut(i) };
            assert_eq!(i, values[pos as usize].get_handle_mut().get_pos());
            assert_eq!(true, pos_set.get(&pos).is_none());
            pos_set.insert(pos);
        }
    }

    let value;
    if size - non_heap_size - 1 > 0 {
        let value_pos = heap
            .pop_head(&mut ArrayPosHeapValueUtil::new(values))
            .unwrap();
        value = values[value_pos as usize].value;
        assert_eq!(true, value >= 0);
    } else {
        value = 0;
    }
    let mut sum = value;
    for i in 1..size - non_heap_size - 1 {
        let value_pos = heap
            .pop_head(&mut ArrayPosHeapValueUtil::new(values))
            .unwrap();
        let new_value = values[value_pos as usize].value;
        sum += new_value;
        assert_eq!(true, new_value >= value);
    }
    let expected_sum_pos = heap
        .pop_head(&mut ArrayPosHeapValueUtil::new(values))
        .unwrap() as usize;
    let expected_sum = values[expected_sum_pos].value;
    assert_eq!(expected_sum, sum);

    {
        let mut pos_set = HashSet::new();
        pos_set.insert(HeapHandle::default().get_pos());
        for i in 0..non_heap_size {
            let pos = *unsafe { heap.get_unchecked_mut(i) };
            assert_eq!(i, values[pos as usize].get_handle_mut().get_pos());
            assert_eq!(true, pos_set.get(&pos).is_none());
            pos_set.insert(pos);
        }
        for i in 0..values.len() - 1 {
            if pos_set.get(&(i as u32)).is_none() {
                assert_eq!(
                    HeapHandle::<u32>::NULL_POS as u32,
                    values[i].get_handle_mut().get_pos()
                )
            }
        }
    }
}

#[test]
fn test_removal_and_sort_with_heap_handle_check() {
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        25000u32, 0u32, 24999u32, 0u32, 30000u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 50000u32, 0u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        25000u32, 0u32, 24999u32, 1u32, 30000u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 50000u32, 1u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        25001u32, 1u32, 24999u32, 1u32, 30000u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 50000u32, 1u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        25100u32, 100u32, 24999u32, 100u32, 30000u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 50000u32, 100u32);
}

#[test]
fn test_corner_cases() {
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 10u32, 0u32, 0u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 1u32, 0u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 10u32, 10u32, 0u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 11u32, 0u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 1u32, 0u32, 9u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 10u32, 9u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 9u32, 0u32, 1u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 2u32, 1u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 0u32, 0u32, 10u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 11u32, 10u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 0u32, 1u32, 10u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 12u32, 10u32);
    let (mut heap, mut values) = initialize_heap_with_removals_and_updates(
        10u32, 0u32, 1u32, 9u32, 0u32,
    );
    check_and_sort_heap_array_pos(&mut heap, &mut values, 12u32, 9u32);
}
