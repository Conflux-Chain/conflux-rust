use std::ops::{Add, Mul, Sub};

use super::RootDegree;
use typenum::*;

pub trait SubU1 {
    type Output: Unsigned;
}

impl<T> SubU1 for T
where
    T: Sub<U1>,
    <T as Sub<U1>>::Output: Unsigned,
{
    type Output = <T as Sub<U1>>::Output;
}

// impl<N> RootParam for N where N: Unsigned
//         + IsGreater<U1, Output = True>
//         + Sub<U1>
//         + IsLessOrEqual<U12, Output = True>
//         + SubU1
// {
//
// }

pub trait RootInvParams {}

impl<N: RootDegree, P: Unsigned> RootInvParams for (N, P)
where
    P: Unsigned + Add<U1>,
    N: RootDegree + Mul<<P as Add<U1>>::Output>,
    <N as Mul<<P as Add<U1>>::Output>>::Output:
        IsLessOrEqual<U256, Output = True>,
{
}
