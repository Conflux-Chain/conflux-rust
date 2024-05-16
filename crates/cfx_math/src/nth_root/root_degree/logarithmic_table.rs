use super::RootDegree;
use typenum::{U2, U3, U4, U5};
use unroll::unroll_for_loops;

struct LookupParam {
    pow: u32,
    max: usize,
    last_max: usize,
    first_root: u8,
}

struct Lookup {
    next_root: u8,
    compute: &'static dyn Fn(u64) -> u64,
    #[allow(unused)]
    length: usize,
    #[allow(unused)]
    flag_bit: bool,
    #[allow(unused)]
    step: usize,
    #[allow(unused)]
    skip: usize,
}

struct LookupTableContext<const N: usize> {
    i: usize,
    x: usize,
    next: usize,
    slot: [u8; N],
    pow: u32,
    skip: usize,
    step: usize,
    flag_bit: bool,
}

const fn compute_lookup_table<const N: usize>(
    pow: u32, step: usize, skip: usize, first: usize, flag_bit: bool,
) -> [u8; N] {
    let c = LookupTableContext::<N> {
        i: 0,
        x: first,
        skip,
        next: (first + 1).pow(pow),
        slot: [0u8; N],
        pow,
        step,
        flag_bit,
    };

    let c = compute_lookup_table_inner::<N>(c, N);
    c.slot
}

const fn compute_lookup_table_inner<const N: usize>(
    mut c: LookupTableContext<N>, batch: usize,
) -> LookupTableContext<N> {
    if batch == 1 {
        if c.i < c.skip {
            c.i += 1;
            return c;
        }
        c.slot[c.i] = c.x as u8;
        if (c.i + 1) * c.step >= c.next {
            if (c.i + 1) * c.step > c.next && c.flag_bit {
                c.slot[c.i] |= 0x80;
            }
            c.x += 1;
            c.next = (c.x + 1).pow(c.pow);
        }
        c.i += 1;
        c
    } else {
        let c = compute_lookup_table_inner(c, batch / 2);
        let c = compute_lookup_table_inner(c, batch / 2);
        c
    }
}

#[unroll_for_loops]
const fn estimate_step_size(pow: u32, start_root: u8) -> usize {
    let mut root: usize = start_root as usize;
    let mut max_leading_zero = 0;
    for i in 0..10 {
        if let (Some(a), Some(b)) =
            (root.checked_pow(pow), (root + 1).checked_pow(pow))
        {
            let this_leading_zero = ((a - 1) ^ (b - 1)).leading_zeros();
            if this_leading_zero > max_leading_zero {
                max_leading_zero = this_leading_zero
            }
        }
        root += 1;
    }
    if let (Some(a), Some(b)) =
        (root.checked_pow(pow), (root + 1).checked_pow(pow))
    {
        let this_leading_zero = (b - a).leading_zeros();
        if this_leading_zero > max_leading_zero {
            max_leading_zero = this_leading_zero
        }
    }
    1 << (usize::BITS - 1 - max_leading_zero) as usize
}

macro_rules! build_lookup {
    ($param:ident) => {{
        const FULL_HOUSE: bool =
            $param.pow < 8 && ($param.max as u64 == (1u64 << (8 * $param.pow)));
        const STEP: usize = estimate_step_size($param.pow, $param.first_root);
        const LENGTH: usize = $param.max / STEP;
        const SKIP: usize = $param.last_max / STEP;
        const FLAG_BIT: bool = STEP > 1 && !FULL_HOUSE;

        const LOOKUP: [u8; LENGTH] = compute_lookup_table(
            $param.pow,
            STEP,
            SKIP,
            $param.first_root as usize,
            FLAG_BIT,
        );

        #[inline]
        const fn compute(input: u64) -> u64 {
            let ans = LOOKUP[input as usize / STEP];
            let (flag, root) = if FLAG_BIT {
                ((ans & 0x80) > 0, (ans & 0x7f) as u64)
            } else {
                (true, ans as u64)
            };
            if !flag || (root + 1).pow($param.pow) > input {
                root
            } else {
                root + 1
            }
        }

        const LAST_ROOT: u8 = if FLAG_BIT {
            LOOKUP[LENGTH - 1] & 0x7f
        } else {
            LOOKUP[LENGTH - 1]
        };
        const NEXT_ROOT: u8 =
            if (LAST_ROOT as u64 + 1).pow($param.pow) > $param.max as u64 {
                LAST_ROOT
            } else {
                LAST_ROOT.overflowing_add(1).0
            };
        Lookup {
            length: LENGTH,
            next_root: NEXT_ROOT,
            compute: &compute,
            flag_bit: FLAG_BIT,
            step: STEP,
            skip: SKIP,
        }
    }};
}

macro_rules! init_lookup_params {
    (pow: $pow:expr, $max:expr) => {{
        LookupParam {
            pow: $pow,
            max: $max,
            last_max: 4usize.pow($pow),
            first_root: 4,
        }
    }};
}

macro_rules! build_lookup_params {
    ($last_param:ident, $last_build:ident, $max:expr) => {{
        LookupParam {
            pow: $last_param.pow,
            max: $max,
            last_max: $last_param.max,
            first_root: $last_build.next_root,
        }
    }};
}

#[inline]
const fn nth_root_lookup_in_nibble<const N: u32>(input: u64) -> Option<u64> {
    if input < 4u64.pow(N) {
        if input >= 3u64.pow(N) {
            Some(3)
        } else if input >= 2u64.pow(N) {
            Some(2)
        } else if input >= 1 {
            Some(1)
        } else {
            Some(0)
        }
    } else {
        None
    }
}

#[inline]
pub fn sqrt_lookup(input: u64) -> u64 {
    assert!(input < 1 << U2::LOOKUP_BITS);
    if let Some(ans) = nth_root_lookup_in_nibble::<2>(input) {
        return ans;
    }

    const P1: LookupParam = LookupParam {
        pow: 2,
        max: 1 << 9,
        last_max: 16,
        first_root: 4,
    };
    const B1: Lookup = build_lookup!(P1);
    const P2: LookupParam = build_lookup_params!(P1, B1, 1 << 12);
    const B2: Lookup = build_lookup!(P2);
    const P3: LookupParam = build_lookup_params!(P2, B2, 1 << U2::LOOKUP_BITS);
    const B3: Lookup = build_lookup!(P3);

    if input < P1.max as u64 {
        return (B1.compute)(input);
    }
    if input < P2.max as u64 {
        return (B2.compute)(input);
    }
    if input < P3.max as u64 {
        return (B3.compute)(input);
    }
    unreachable!();
}

pub fn cbrt_lookup(input: u64) -> u64 {
    assert!(input < 1 << U3::LOOKUP_BITS);
    if let Some(ans) = nth_root_lookup_in_nibble::<3>(input) {
        return ans;
    }

    const P1: LookupParam = init_lookup_params!(pow: 3, 1<<12);
    const B1: Lookup = build_lookup!(P1);
    const P2: LookupParam = build_lookup_params!(P1, B1, 1 << 16);
    const B2: Lookup = build_lookup!(P2);
    const P3: LookupParam = build_lookup_params!(P2, B2, 1 << U3::LOOKUP_BITS);
    const B3: Lookup = build_lookup!(P3);

    if input < P1.max as u64 {
        return (B1.compute)(input);
    }
    if input < P2.max as u64 {
        return (B2.compute)(input);
    }
    if input < P3.max as u64 {
        return (B3.compute)(input);
    }
    unreachable!();
}

pub fn rt4_lookup(input: u64) -> u64 {
    assert!(input < 1 << U4::LOOKUP_BITS);
    if let Some(ans) = nth_root_lookup_in_nibble::<4>(input) {
        return ans;
    }

    const P1: LookupParam = init_lookup_params!(pow: 4, 1<<15);
    const B1: Lookup = build_lookup!(P1);
    const P2: LookupParam = build_lookup_params!(P1, B1, 1 << 20);
    const B2: Lookup = build_lookup!(P2);
    const P3: LookupParam = build_lookup_params!(P2, B2, 1 << U4::LOOKUP_BITS);
    const B3: Lookup = build_lookup!(P3);

    if input < P1.max as u64 {
        return (B1.compute)(input);
    }
    if input < P2.max as u64 {
        return (B2.compute)(input);
    }
    if input < P3.max as u64 {
        return (B3.compute)(input);
    }
    unreachable!();
}

pub fn rt5_lookup(input: u64) -> u64 {
    assert!(input < 1 << U5::LOOKUP_BITS);
    if let Some(ans) = nth_root_lookup_in_nibble::<5>(input) {
        return ans;
    }

    const P1: LookupParam = init_lookup_params!(pow: 5, 1 << 17);
    const B1: Lookup = build_lookup!(P1);
    const P2: LookupParam = build_lookup_params!(P1, B1, 1 << 22);
    const B2: Lookup = build_lookup!(P2);
    const P3: LookupParam = build_lookup_params!(P2, B2, 1 << 28);
    const B3: Lookup = build_lookup!(P3);

    if input < P1.max as u64 {
        return (B1.compute)(input);
    }
    if input < P2.max as u64 {
        return (B2.compute)(input);
    }
    if input < P3.max as u64 {
        return (B3.compute)(input);
    }
    unreachable!();
}
