use cfx_types::{U256, U512};
use std::{
    convert::TryFrom,
    fmt::Debug,
    ops::{Add, Div, Mul, Shl, Shr, Sub},
};
use typenum::Unsigned;

use super::{const_generic::SubU1, root_degree::RootDegree};
use unroll::unroll_for_loops;

pub trait NthRoot:
    Copy
    + Mul<Output = Self>
    + Ord
    + Shl<usize, Output = Self>
    + Shr<usize, Output = Self>
    + Div<Output = Self>
    + Add<Output = Self>
    + Sub<Output = Self>
    + From<u64>
    + Debug
{
    const BITS: usize;
    const MAX: Self;

    fn checked_mul(self, other: Self) -> Option<Self>;
    fn mul_usize(self, other: usize) -> Self;
    fn div_usize(self, other: usize) -> Self;
    fn bits(self) -> usize;
    fn init_root<N: RootDegree>(self) -> InitRoot<Self>;

    #[inline]
    fn nth_root<N: RootDegree>(self) -> Self {
        match self.init_root::<N>() {
            InitRoot::Init(init_root) => {
                newtons_method::<N, _>(self, init_root)
            }
            InitRoot::Done(root) => root,
        }
    }

    #[inline]
    fn truncate(self, next_bits: usize, multiply: usize) -> (Self, usize) {
        let bits = self.bits();
        let significant_bits = {
            let n = multiply;
            let adjust_bits = (n + (next_bits % n) - bits % n) % n;
            next_bits - adjust_bits
        };

        // The `rest_bits` must be multiply of N.
        let rest_bits = bits - significant_bits;
        let significant_word = self >> rest_bits;
        (significant_word, rest_bits)
    }
}

pub enum InitRoot<I> {
    Init(I),
    Done(I),
}

#[inline]
fn check_answer<const N: u32>(input: u64, output: u64) -> bool {
    (output).checked_pow(N).map_or(false, |x| x <= input)
        && (output + 1).checked_pow(N).map_or(true, |x| x > input)
}

impl NthRoot for u64 {
    const BITS: usize = 64;
    const MAX: u64 = u64::MAX;

    #[inline]
    fn checked_mul(self, other: Self) -> Option<Self> {
        self.checked_mul(other)
    }

    #[inline]
    fn mul_usize(self, other: usize) -> Self { self * (other as u64) }

    #[inline]
    fn div_usize(self, other: usize) -> Self { self / (other as u64) }

    #[inline]
    fn bits(self) -> usize { (u64::BITS - self.leading_zeros()) as usize }

    #[inline]
    fn init_root<N: RootDegree>(self) -> InitRoot<Self> {
        if self == 0 {
            return InitRoot::Done(0);
        }
        if self < 1 << N::USIZE {
            return InitRoot::Done(1);
        }

        if N::USIZE == 2 {
            let ans = (self as f64).sqrt() as u64;
            if check_answer::<2>(self, ans) {
                return InitRoot::Done(ans);
            }
            return InitRoot::Init(ans + 1);
        }

        if N::USIZE == 4 {
            let ans = (self as f64).sqrt().sqrt() as u64;
            if check_answer::<4>(self, ans) {
                return InitRoot::Done(ans);
            }
            return InitRoot::Init(ans + 1);
        }

        if N::LOOKUP_BITS > 0 {
            if self < (1 << N::LOOKUP_BITS) - 1 {
                InitRoot::Done(N::nth_root_lookup(self))
            } else {
                let (small, rot) =
                    self.truncate(N::LOOKUP_BITS as usize, N::USIZE);
                InitRoot::Init(
                    (N::nth_root_lookup(small) + 1) << (rot / N::USIZE),
                )
            }
        } else {
            InitRoot::Init(
                ((self as f64).ln() / f64::from(N::U32)).exp() as u64 + 1,
            )
        }
    }
}

impl NthRoot for u128 {
    const BITS: usize = 128;
    const MAX: u128 = u128::MAX;

    #[inline]
    fn checked_mul(self, other: Self) -> Option<Self> {
        self.checked_mul(other)
    }

    #[inline]
    fn mul_usize(self, other: usize) -> Self { self * (other as u128) }

    #[inline]
    fn div_usize(self, other: usize) -> Self { self / (other as u128) }

    #[inline]
    fn bits(self) -> usize { (u128::BITS - self.leading_zeros()) as usize }

    #[inline]
    fn init_root<N: RootDegree>(self) -> InitRoot<Self> {
        let compute_next = |me: u128| (me as u64).nth_root::<N>() as u128;
        if self < u64::MAX as u128 {
            InitRoot::Done(compute_next(self))
        } else {
            InitRoot::Init({
                let (next, rot) = self.truncate(64, N::USIZE);
                (compute_next(next) + 1) << (rot / N::USIZE)
            })
        }
    }
}

impl NthRoot for U256 {
    const BITS: usize = 256;
    const MAX: U256 = U256::MAX;

    #[inline]
    fn checked_mul(self, other: Self) -> Option<Self> {
        self.checked_mul(other)
    }

    #[inline]
    fn mul_usize(self, other: usize) -> Self { self * other }

    #[inline]
    fn div_usize(self, other: usize) -> Self { self / other }

    #[inline]
    fn bits(self) -> usize { U256::bits(&self) }

    #[inline]
    fn init_root<N: RootDegree>(self) -> InitRoot<Self> {
        let compute_next = |me: U256| U256::from(me.as_u128().nth_root::<N>());
        if &self.0[2..4] == &[0, 0] {
            InitRoot::Done(compute_next(self))
        } else {
            InitRoot::Init({
                let (next, rot) = self.truncate(128, N::USIZE);
                (compute_next(next) + 1) << (rot / N::USIZE)
            })
        }
    }
}

impl NthRoot for U512 {
    const BITS: usize = 512;
    const MAX: U512 = U512::MAX;

    #[inline]
    fn checked_mul(self, other: Self) -> Option<Self> {
        self.checked_mul(other)
    }

    #[inline]
    fn mul_usize(self, other: usize) -> Self { self * other }

    #[inline]
    fn div_usize(self, other: usize) -> Self { self / other }

    #[inline]
    fn bits(self) -> usize { U512::bits(&self) }

    #[inline]
    fn init_root<N: RootDegree>(self) -> InitRoot<Self> {
        let compute_next =
            |me: U512| U512::from(U256::try_from(me).unwrap().nth_root::<N>());
        if &self.0[4..8] == &[0, 0, 0, 0] {
            InitRoot::Done(compute_next(self))
        } else {
            InitRoot::Init({
                let (next, rot) = self.truncate(256, N::USIZE);
                (compute_next(next) + 1) << (rot / N::USIZE)
            })
        }
    }
}

#[inline]
fn newtons_method<N: RootDegree, I: NthRoot>(input: I, init_root: I) -> I {
    let mut root = init_root;
    loop {
        let pow_n_1 = pow::<<N as SubU1>::Output, I>(root);
        let pow_n = pow_n_1.checked_mul(root);

        if pow_n.map_or(false, |x| x <= input) {
            return root;
        }

        let mut fast_compute_root = None;
        if I::BITS == 256 {
            if let Some(pow_n) = pow_n {
                let divisor = pow_n_1.mul_usize(N::USIZE);
                fast_compute_root = Some(
                    root - (pow_n - input - 1.into()) / divisor - 1.into(),
                );
            }
        }
        root = if let Some(root) = fast_compute_root {
            root
        } else {
            (input / pow_n_1 + root.mul_usize(N::USIZE - 1)).div_usize(N::USIZE)
        };
    }
}

#[inline]
#[allow(unused_assignments)]
#[unroll_for_loops]
pub(super) fn pow<N: Unsigned, I: Copy + From<u64> + Mul<Output = I>>(
    input: I,
) -> I {
    let pow = N::USIZE;
    match pow {
        0 => {
            return I::from(1u64);
        }
        1 => {
            return input;
        }
        2 => {
            return input * input;
        }
        3 => {
            return input * input * input;
        }
        _ => {}
    }

    let mut base = input;
    let mut acc = I::from(1u64);

    for bit in 0u32..32 {
        if (pow & (1 << bit)) > 0 {
            acc = acc * base
        }
        if bit < 31 && (pow >> (bit + 1)) > 0 {
            base = base * base
        }
    }
    acc
}
