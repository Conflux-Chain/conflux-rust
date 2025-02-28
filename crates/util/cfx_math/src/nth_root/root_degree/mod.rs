mod exponential_table;
mod logarithmic_table;

use self::exponential_table::{make_table_u32, make_table_u64, search_table};
pub use self::logarithmic_table::{
    cbrt_lookup, rt4_lookup, rt5_lookup, sqrt_lookup,
};
use super::const_generic::SubU1;
use typenum::{Unsigned, U10, U11, U12, U2, U3, U4, U5, U6, U7, U8, U9};

pub trait RootDegree: Unsigned + SubU1 {
    const LOOKUP_BITS: u32 = 0;

    fn nth_root_lookup(_input: u64) -> u64 { unimplemented!() }
}

impl RootDegree for U2 {
    const LOOKUP_BITS: u32 = 16;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 { sqrt_lookup(input) }
}

impl RootDegree for U3 {
    const LOOKUP_BITS: u32 = 20;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 { cbrt_lookup(input) }
}

impl RootDegree for U4 {
    const LOOKUP_BITS: u32 = 25;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 { rt4_lookup(input) }
}

impl RootDegree for U5 {
    const LOOKUP_BITS: u32 = 28;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 { rt5_lookup(input) }
}
impl RootDegree for U6 {
    const LOOKUP_BITS: u32 = 30;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u32; 32] = make_table_u32(6);
        search_table::<_, 32>(input, &TABLE, 6)
    }
}
impl RootDegree for U7 {
    const LOOKUP_BITS: u32 = 28;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u32; 16] = make_table_u32(7);
        search_table::<_, 16>(input, &TABLE, 7)
    }
}
impl RootDegree for U8 {
    const LOOKUP_BITS: u32 = 32;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u32; 16] = make_table_u32(8);
        search_table::<_, 16>(input, &TABLE, 8)
    }
}
impl RootDegree for U9 {
    const LOOKUP_BITS: u32 = 36;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u64; 16] = make_table_u64(9);
        search_table::<_, 16>(input, &TABLE, 9)
    }
}
impl RootDegree for U10 {
    const LOOKUP_BITS: u32 = 40;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u64; 16] = make_table_u64(10);
        search_table::<_, 16>(input, &TABLE, 10)
    }
}
impl RootDegree for U11 {
    const LOOKUP_BITS: u32 = 44;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u64; 16] = make_table_u64(11);
        search_table::<_, 16>(input, &TABLE, 11)
    }
}
impl RootDegree for U12 {
    const LOOKUP_BITS: u32 = 48;

    #[inline]
    fn nth_root_lookup(input: u64) -> u64 {
        const TABLE: [u64; 16] = make_table_u64(12);
        search_table::<_, 16>(input, &TABLE, 12)
    }
}
