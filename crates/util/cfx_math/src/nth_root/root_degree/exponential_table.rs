use unroll::unroll_for_loops;

#[unroll_for_loops]
pub(super) const fn make_table_u32<const N: usize>(pow: u32) -> [u32; N] {
    let mut ans = [0; N];
    for i in 0..64 {
        if i < N {
            let val = (i + 2).pow(pow);
            ans[i] = if val > u32::MAX as usize {
                // zero represents infinity
                0
            } else {
                val as u32
            };
        }
    }
    ans
}

#[unroll_for_loops]
pub(super) const fn make_table_u64<const N: usize>(pow: u32) -> [u64; N] {
    let mut ans = [0; N];
    for i in 0..64 {
        if i < N {
            ans[i] = (i + 2).pow(pow) as u64;
        }
    }
    ans
}

#[inline]
pub(super) fn search_table<I: Copy + Into<u64>, const N: usize>(
    input: u64, table: &[I; N], pow: u32,
) -> u64 {
    if input < 1 << pow {
        return if input >= 1 { 1 } else { 0 };
    }

    let mut index = N / 2;
    let mut step = N / 2;
    while step > 1 {
        step /= 2;
        let val = table[index].into();
        if input < val || val == 0 {
            index -= step;
        } else {
            index += step;
        }
    }

    let val = table[index].into();
    2 + if input < val || val == 0 {
        index as u64 - 1
    } else {
        index as u64
    }
}
