// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// The trait automatically implements for D: Deref with D::Target. User may add
/// implementation of DerefPlusSelf<Target = Type> for some Type
/// via enable_deref_for_self, where Type can be str, [T], or a local type (i.e.
/// not an upstream type).
pub trait DerefPlusSelf {
    type Target: ?Sized;

    fn deref(&self) -> &Self::Target;
}

pub trait DerefMutPlusSelf {
    type Target: ?Sized;

    fn deref_mut(&mut self) -> &mut Self::Target;
}

/// We can not impl DerefPlusSelf automatically for a general T because it
/// would conflict with the blanket implementation for D: Deref below, because
/// the compiler can not rule out the possibility for D: Deref + Sized with
/// D::Target == D. For a local type, compiler will first check if Deref is
/// implemented for that type, and if D::Target == D.
macro_rules! enable_deref_for_self {
    ($type:ty) => {
        impl DerefPlusSelf for $type {
            type Target = Self;

            fn deref(&self) -> &Self {
                self
            }
        }
        impl DerefMutPlusSelf for $type {
            type Target = Self;

            fn deref_mut(&mut self) -> &mut Self {
                self
            }
        }
    };
}

impl<D: Deref<Target = T>, T: ?Sized> DerefPlusSelf for D {
    type Target = T;

    fn deref(&self) -> &T {
        Deref::deref(self)
    }
}

impl<D: DerefMut<Target = T>, T: ?Sized> DerefMutPlusSelf for D {
    type Target = T;

    fn deref_mut(&mut self) -> &mut T {
        DerefMut::deref_mut(self)
    }
}

/// This trait is automatically implemented for the Trait ifself, any type which
/// implements Trait, and any Borrow of the Trait.
pub trait ImplOrBorrowSelf<Trait: ?Sized> {
    fn borrow(&self) -> &Trait;
}

/// This trait is automatically implemented for the Trait ifself, any type which
/// implements Trait, and any BorrowMut of the Trait.
pub trait ImplOrBorrowMutSelf<Trait: ?Sized> {
    fn borrow_mut(&mut self) -> &mut Trait;
}

/// Suppose you have a trait Trait and some type T: Trait, this trait is
/// automatically implemented for Trait itself, &Tr, Box<Tr>, Arc<Tr>, &T,
/// Box<T>, Arc<T>, etc. When DerefPlusSelf is implemented for T, this trait is
/// also implemented for T.
pub trait DerefPlusImplOrBorrowSelf<T: ?Sized> {
    fn borrow(&self) -> &T;
}

pub trait DerefMutPlusImplOrBorrowMutSelf<T: ?Sized> {
    fn borrow_mut(&mut self) -> &mut T;
}

/// We can not impl DerefPlusImplOrBorrowSelf automatically for a general Trait
/// because it would conflict with the blanket implementation for D:
/// DerefPlusSelf,
///
/// For trait, they are !Sized so compiler knows for sure that implementation
/// for D isn't possible.
macro_rules! enable_deref_plus_impl_or_borrow_self {
    ($trait:path) => {
        impl<'a> ImplOrBorrowSelf<dyn 'a + $trait> for dyn 'a + $trait {
            fn borrow(&self) -> &(dyn 'a + $trait) {
                self
            }
        }

        impl<'a> ImplOrBorrowSelf<dyn 'a + $trait> for &(dyn 'a + $trait) {
            fn borrow(&self) -> &(dyn 'a + $trait) {
                *self
            }
        }

        impl<'a, T: 'a + $trait> ImplOrBorrowSelf<dyn 'a + $trait> for T {
            fn borrow(&self) -> &(dyn 'a + $trait) {
                self
            }
        }

        impl<'a> DerefPlusImplOrBorrowSelf<dyn 'a + $trait>
            for dyn 'a + $trait
        {
            fn borrow(&self) -> &(dyn 'a + $trait) {
                self
            }
        }

        impl<
                'a,
                D: DerefPlusSelf<Target = T>,
                T: 'a + ImplOrBorrowSelf<dyn 'a + $trait> + ?Sized,
            > DerefPlusImplOrBorrowSelf<dyn 'a + $trait> for D
        {
            fn borrow(&self) -> &(dyn 'a + $trait) {
                <T as ImplOrBorrowSelf<dyn 'a + $trait>>::borrow(self.deref())
            }
        }
    };
}

macro_rules! enable_deref_mut_plus_impl_or_borrow_mut_self {
    ($trait:path) => {
        impl<'a> ImplOrBorrowMutSelf<dyn 'a + $trait> for dyn 'a + $trait {
            fn borrow_mut(&mut self) -> &mut (dyn 'a + $trait) {
                self
            }
        }

        impl<'a> ImplOrBorrowMutSelf<dyn 'a + $trait>
            for &mut (dyn 'a + $trait)
        {
            fn borrow_mut(&mut self) -> &mut (dyn 'a + $trait) {
                *self
            }
        }

        impl<'a, T: 'a + $trait> ImplOrBorrowMutSelf<dyn 'a + $trait> for T {
            fn borrow_mut(&mut self) -> &mut (dyn 'a + $trait) {
                self
            }
        }

        impl<'a> DerefMutPlusImplOrBorrowMutSelf<dyn 'a + $trait>
            for dyn 'a + $trait
        {
            fn borrow_mut(&mut self) -> &mut (dyn 'a + $trait) {
                self
            }
        }

        impl<
                'a,
                D: DerefMutPlusSelf<Target = T>,
                T: 'a + ImplOrBorrowMutSelf<dyn 'a + $trait> + ?Sized,
            > DerefMutPlusImplOrBorrowMutSelf<dyn 'a + $trait> for D
        {
            fn borrow_mut(&mut self) -> &mut (dyn 'a + $trait) {
                <T as ImplOrBorrowMutSelf<dyn 'a + $trait>>::borrow_mut(
                    self.deref_mut(),
                )
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    enable_deref_for_self!(str);
    enable_deref_for_self!([u8]);
    enable_deref_for_self!(my_vec::MyVec<u8>);

    enable_deref_plus_impl_or_borrow_self!(TestTrait);
    enable_deref_for_self!(Test);

    trait TestTrait {
        fn print(&self, x: i32) {
            println!("{}", x);
        }
    }
    struct Test {}
    mod my_vec {
        pub struct MyVec<T>(pub Vec<T>);
    }

    impl TestTrait for Test {}

    /// Don't run, just check for compilation.
    #[allow(unused)]
    fn test<'a>(x: &'a i32) {
        let test = Test {};
        <Test as DerefPlusImplOrBorrowSelf<dyn TestTrait>>::borrow(&test)
            .print(*x);
        <&Test as DerefPlusImplOrBorrowSelf<dyn TestTrait>>::borrow(&&test)
            .print(*x);
        let boxed: Box<dyn 'a + TestTrait> = Box::new(test);
        <dyn 'a + TestTrait as DerefPlusImplOrBorrowSelf<dyn 'a + TestTrait>>::borrow(
            Deref::deref(&boxed),
        )
        .print(*x);
        <&(dyn 'a + TestTrait) as DerefPlusImplOrBorrowSelf<
            dyn 'a + TestTrait,
        >>::borrow(&Deref::deref(&boxed))
        .print(*x);
        <Box<dyn 'a + TestTrait> as DerefPlusImplOrBorrowSelf<
            dyn 'a + TestTrait,
        >>::borrow(&boxed)
        .print(*x);
    }
}

use std::ops::{Deref, DerefMut};
