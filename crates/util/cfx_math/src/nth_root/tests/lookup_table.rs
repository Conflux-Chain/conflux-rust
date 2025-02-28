use super::RootDegree;
use typenum::{U10, U11, U12, U2, U3, U4, U5, U6, U7, U8, U9};

#[test]
fn test_lookup_table() {
    for i in 0u64..(1 << U2::LOOKUP_BITS) {
        let root = U2::nth_root_lookup(i);
        assert!(root.pow(2) <= i);
        assert!((root + 1).pow(2) > i);
    }

    for i in 0u64..(1 << U3::LOOKUP_BITS) {
        let root = U3::nth_root_lookup(i);
        assert!(root.pow(3) <= i);
        assert!((root + 1).pow(3) > i);
    }
    for i in 0u64..(1 << U4::LOOKUP_BITS) {
        let root = U4::nth_root_lookup(i);
        assert!(root.pow(4) <= i);
        assert!((root + 1).pow(4) > i);
    }
    for i in 0u64..(1 << U5::LOOKUP_BITS) {
        let root = U5::nth_root_lookup(i);
        assert!(root.pow(5) <= i);
        assert!((root + 1).pow(5) > i);
    }
    test_lookup_table_inner::<U6>(32);
    test_lookup_table_inner::<U7>(16);
    test_lookup_table_inner::<U8>(16);
    test_lookup_table_inner::<U9>(16);
    test_lookup_table_inner::<U10>(16);
    test_lookup_table_inner::<U11>(16);
    test_lookup_table_inner::<U12>(16);
}

fn test_lookup_table_inner<N: RootDegree>(max: u64) {
    assert_eq!(N::nth_root_lookup(0), 0);
    for i in 1u64..max {
        assert_eq!(N::nth_root_lookup(i.pow(N::U32)), i);
        assert_eq!(N::nth_root_lookup(i.pow(N::U32) + 1), i);
        assert_eq!(N::nth_root_lookup((i + 1).pow(N::U32) - 1), i);
    }
}
