use cfx_types::{U256, U512};

pub trait Zero: PartialEq + Sized {
    fn zero() -> Self;
    fn is_zero(&self) -> bool { self == &Self::zero() }
}

macro_rules! impl_zero_by_lit {
    (lit: $lit: literal, $ty: ident) => {
        impl_zero_by_lit!(@inner, $ty, $lit);
    };
    (lit: $lit: literal, $ty: ident, $($rest: ident),*) => {
        impl_zero_by_lit!(@inner, $ty, $lit);
        impl_zero_by_lit!(lit: $lit, $($rest),*);
    };
    (@inner, $name: ident, $lit: literal) => {
        impl Zero for $name {
            fn zero() -> Self {
                $lit
            }

            fn is_zero(&self) -> bool {
                *self == $lit
            }
        }
    };
}

impl_zero_by_lit!(
    lit: 0,
    usize,
    u8,
    u16,
    u32,
    u64,
    u128,
    isize,
    i8,
    i16,
    i32,
    i64,
    i128
);
impl_zero_by_lit!(lit: 0.0, f32, f64);

impl Zero for U256 {
    fn zero() -> Self { Self::zero() }

    fn is_zero(&self) -> bool { self.is_zero() }
}

impl Zero for U512 {
    fn zero() -> Self { Self::zero() }

    fn is_zero(&self) -> bool { self.is_zero() }
}
