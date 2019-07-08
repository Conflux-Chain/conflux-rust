// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

lazy_static! {
    static ref NEW_CHILDREN_VALUE: NodeRefDeltaMptCompact =
        NodeRefDeltaMptCompact::new(CHILDREN_COUNT as u32);
}

fn default_children_value(index: u8) -> NodeRefDeltaMptCompact {
    NodeRefDeltaMptCompact::new(index.into())
}

fn enumerate_and_test<
    F: FnMut([bool; CHILDREN_COUNT], Vec<u8>, ChildrenTableDeltaMpt),
>(
    mut checker: F,
) {
    do_enumerate(
        0,
        [false; CHILDREN_COUNT],
        Vec::with_capacity(CHILDREN_COUNT),
        ChildrenTableDeltaMpt::default(),
        &mut checker,
    );
}

fn do_enumerate<
    F: FnMut([bool; CHILDREN_COUNT], Vec<u8>, ChildrenTableDeltaMpt),
>(
    index: u8, mut existence: [bool; CHILDREN_COUNT], mut list: Vec<u8>,
    children_table: ChildrenTableDeltaMpt, checker: &mut F,
)
{
    if index as usize == CHILDREN_COUNT {
        checker(existence, list, children_table)
    } else {
        do_enumerate(
            index + 1,
            existence.clone(),
            list.clone(),
            children_table.clone(),
            checker,
        );
        existence[index as usize] = true;
        list.push(index);
        do_enumerate(
            index + 1,
            existence,
            list,
            unsafe {
                ChildrenTableDeltaMpt::insert_child_unchecked(
                    children_table.to_ref(),
                    index,
                    default_children_value(index),
                )
            },
            checker,
        );
    }
}

#[test]
/// When children_count is 0, the table_ptr must be null.
/// If the table_ptr is an "empty array" there could be memory leak.
fn test_no_alloc_in_empty_children_table() {
    let empty_children_table = ChildrenTableDeltaMpt::default();
    empty_children_table.assert_no_alloc_in_empty_children_table();
    let cloned_table = empty_children_table.clone();
    cloned_table.assert_no_alloc_in_empty_children_table();

    let rlp_bytes = empty_children_table.to_ref().rlp_bytes();
    let rlp_parsed =
        ChildrenTableManagedDeltaMpt::decode(&Rlp::new(rlp_bytes.as_slice()))
            .unwrap();
    let decoded_table = ChildrenTableDeltaMpt::from(rlp_parsed);
    decoded_table.assert_no_alloc_in_empty_children_table();

    let index = 3;
    let one_element_table = unsafe {
        ChildrenTableDeltaMpt::insert_child_unchecked(
            empty_children_table.to_ref(),
            index,
            default_children_value(index),
        )
    };
    let cleared_table = unsafe {
        ChildrenTableDeltaMpt::delete_child_unchecked(
            one_element_table.to_ref(),
            index,
        )
    };
    cleared_table.assert_no_alloc_in_empty_children_table();
}

#[test]
fn test_children_table_updates() {
    enumerate_and_test(|existence, children_list, children_table| {
        // Enumerate updates.
        for i in 0..CHILDREN_COUNT as u8 {
            let mut children_table = children_table.clone();
            if existence[i as usize] {
                // Test update.
                unsafe {
                    children_table.set_child_unchecked(i, *NEW_CHILDREN_VALUE);
                }
                assert_eq!(
                    children_list.len(),
                    children_table.get_children_count() as usize
                );
                for j in 0..CHILDREN_COUNT as u8 {
                    let child = children_table.get_child(j);
                    if j == i {
                        assert_eq!(child, Some(*NEW_CHILDREN_VALUE));
                    } else if !existence[j as usize] {
                        assert_eq!(child, None);
                    } else {
                        assert_eq!(child, Some(default_children_value(j)));
                    }
                }
                // Test deletion.
                children_table = unsafe {
                    ChildrenTableDeltaMpt::delete_child_unchecked(
                        children_table.to_ref(),
                        i,
                    )
                };
                assert_eq!(
                    children_list.len() - 1,
                    children_table.get_children_count() as usize
                );
                for j in 0..CHILDREN_COUNT as u8 {
                    let child = children_table.get_child(j);
                    if j == i || !existence[j as usize] {
                        assert_eq!(child, None);
                    } else {
                        assert_eq!(child, Some(default_children_value(j)))
                    }
                }
            } else {
                // Test insertion.
                children_table = unsafe {
                    ChildrenTableDeltaMpt::insert_child_unchecked(
                        children_table.to_ref(),
                        i,
                        *NEW_CHILDREN_VALUE,
                    )
                };
                assert_eq!(
                    children_list.len() + 1,
                    children_table.get_children_count() as usize
                );
                for j in 0..CHILDREN_COUNT as u8 {
                    let child = children_table.get_child(j);
                    if j == i {
                        assert_eq!(child, Some(*NEW_CHILDREN_VALUE));
                    } else if !existence[j as usize] {
                        assert_eq!(child, None);
                    } else {
                        assert_eq!(child, Some(default_children_value(j)));
                    }
                }
            }
        }
    });
}

#[test]
fn test_children_table_type_conversions() {
    enumerate_and_test(|_existence, _children_list, children_table| {
        assert_eq!(children_table, children_table.clone());

        let children_table_ref = children_table.to_ref();
        assert_eq!(children_table, children_table_ref.clone().into());

        let children_table_manager = ChildrenTableManagedDeltaMpt::decode(
            &Rlp::new(&children_table_ref.rlp_bytes()),
        )
        .unwrap();
        assert_eq!(children_table, children_table_manager.into());
    })
}

#[test]
fn test_children_table_iteration() {
    enumerate_and_test(|existence, children_list, mut children_table| {
        // iter()
        let mut list = Vec::with_capacity(CHILDREN_COUNT);
        for (i, children) in children_table.iter() {
            list.push(i);
            assert_eq!(default_children_value(i), *children);
        }
        assert_eq!(children_list, list);

        // iter_mut()
        let mut list = Vec::with_capacity(CHILDREN_COUNT);
        for (i, children) in children_table.iter_mut() {
            list.push(i);
            assert_eq!(default_children_value(i), *children);
        }
        assert_eq!(children_list, list);

        // iter_non_skip()
        let mut next_index = 0usize;
        for (i, maybe_children) in children_table.iter_non_skip() {
            assert_eq!(next_index, i as usize);

            if existence[next_index] {
                assert_eq!(default_children_value(i), *maybe_children.unwrap());
            } else {
                assert_eq!(None, maybe_children);
            }

            next_index = (i + 1).into();
        }
        assert_eq!(next_index, CHILDREN_COUNT);

        // iter_non_skip_mut()
        let mut next_index = 0usize;
        for (i, maybe_children) in children_table.iter_non_skip_mut() {
            assert_eq!(next_index, i as usize);

            if existence[next_index] {
                assert_eq!(default_children_value(i), *maybe_children.unwrap());
            } else {
                assert_eq!(None, maybe_children);
            }

            next_index = (i + 1).into();
        }
        assert_eq!(next_index, CHILDREN_COUNT);
    })
}

#[test]
fn test_children_table_iteration_modification() {
    enumerate_and_test(|existence, children_list, mut children_table| {
        // iter_mut()
        for (i, children) in children_table.iter_mut() {
            *children = NodeRefDeltaMptCompact::new(i as u32 * 3);
        }

        let mut list = Vec::with_capacity(CHILDREN_COUNT);
        for (i, children) in children_table.iter_mut() {
            list.push(i);
            assert_eq!(NodeRefDeltaMptCompact::new(i as u32 * 3), *children);
        }
        assert_eq!(children_list, list);

        // iter_non_skip_mut()
        for (i, maybe_children) in children_table.iter_non_skip_mut() {
            match maybe_children {
                None => {}
                Some(children) => {
                    *children = NodeRefDeltaMptCompact::new(i as u32 * 5);
                }
            }
        }

        let mut next_index = 0usize;
        for (i, maybe_children) in children_table.iter_non_skip_mut() {
            assert_eq!(next_index, i as usize);

            if existence[next_index] {
                assert_eq!(
                    NodeRefDeltaMptCompact::new(i as u32 * 5),
                    *maybe_children.unwrap()
                );
            } else {
                assert_eq!(None, maybe_children);
            }

            next_index = (i + 1).into();
        }
        assert_eq!(next_index, CHILDREN_COUNT);
    })
}

use super::super::{children_table::*, *};
use lazy_static::lazy_static;
use rlp::*;
