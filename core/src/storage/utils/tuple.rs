// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use placeholders::PLACEHOLDERS;

pub trait IndexGetExt<T>: TupleIndex {
    type ElementType;

    fn get_impl<'a>(x: &'a T) -> &'a Self::ElementType;
    fn get_mut_impl<'a>(x: &'a mut T) -> &'a mut Self::ElementType;
}

pub trait TestTupleIndexExt<ConcernedTuple> {}

pub trait TupleIndexExt: Sized {
    type IndexMax: TupleIndex;

    fn size_tuple() -> usize;

    fn size(&self) -> usize;

    fn get<I: TupleIndex>(
        &self,
    ) -> &<Self as TupleGetIndexExt<I>>::ElementType
    where Self: TupleGetIndexExt<I> {
        self.get_impl()
    }

    fn get_mut<I: TupleIndex>(
        &mut self,
    ) -> &mut <Self as TupleGetIndexExt<I>>::ElementType
    where Self: TupleGetIndexExt<I> {
        self.get_mut_impl()
    }
}

/// We don't support generics and lifetime yet because it will take some time to
/// update the macro implementation.
macro_rules! make_tuple_with_index_ext {
    ( $tuple_struct_name:ident($($element_type:ty$(: $pub_vis:tt)*),*) ) => {
        #[derive(Default, Clone)]
        pub struct $tuple_struct_name($($($pub_vis )*$element_type),*);

        make_get_index_ext_all!{
            $tuple_struct_name($($element_type),*),
            (
                placeholder!(_0), placeholder!(_1), placeholder!(_2),
                placeholder!(_3), placeholder!(_4), placeholder!(_5),
                placeholder!(_6), placeholder!(_7), placeholder!(_8),
                placeholder!(_9), placeholder!(_10), placeholder!(_11),
                placeholder!(_12), placeholder!(_13)
            ),
            (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
        }
    }
}

/// This trait is on Tuple.
pub trait TupleGetIndexExt<I: TupleIndex> {
    type ElementType: ?Sized;

    fn get_impl(&self) -> &Self::ElementType;
    fn get_mut_impl(&mut self) -> &mut Self::ElementType;
}

pub trait IterCallFamilyTrait<
    ConcernedTuple,
    ElementConstrain: ElementConstrainMark + ?Sized,
>
{
    fn prepare_iter(&mut self) {}

    fn iter_step<
        Index: OfElementSatisfiesOnTuple<ConcernedTuple, ElementConstrain>,
    >(
        &mut self, placeholder: &'static Index, index: usize,
    );

    fn finish_iter(&mut self) {}
}

pub trait TupleIterateFromTo<ElementConstrain: ElementConstrainMark + ?Sized>:
    TupleIndexExt + Sized
{
    fn iter_from_to<
        FromIndex: TupleIndex,
        ToIndex: TupleIndex,
        F: IterCallFamilyTrait<Self, ElementConstrain>,
    >(
        _from: &FromIndex, _to: &ToIndex, f: F,
    ) where Self: TupleIterFromTo<FromIndex, ToIndex, ElementConstrain> {
        <Self as TupleIterFromTo<FromIndex, ToIndex, ElementConstrain>>::iterate_from_to(f);
    }
}

pub trait TupleIterate<ElementConstrain: ElementConstrainMark + ?Sized>:
    Sized
{
    fn iterate<F: IterCallFamilyTrait<Self, ElementConstrain>>(f: F);
}

pub trait TupleIterFromTo<
    FromIndex: TupleIndex,
    ToIndex: TupleIndex,
    ElementConstrain: ElementConstrainMark + ?Sized,
>: Sized
{
    fn iterate_from_to<F: IterCallFamilyTrait<Self, ElementConstrain>>(f: F);
}

impl<T: TupleIndexExt, ElementConstrain: ElementConstrainMark + ?Sized>
    TupleIterateFromTo<ElementConstrain> for T
{
}

impl<
        T: TupleIndexExt
            + TupleIterFromTo<
                placeholders::_0,
                <Self as TupleIndexExt>::IndexMax,
                ElementConstrain,
            >,
        ElementConstrain: ElementConstrainMark + ?Sized,
    > TupleIterate<ElementConstrain> for T
{
    fn iterate<F: IterCallFamilyTrait<Self, ElementConstrain>>(f: F) {
        Self::iterate_from_to(f);
    }
}

// So far we don't support ElementType that is non 'static because rust
// automatically add 'static to ElementContrain since it is a trait object.
// It would require more time to add support for ElementType with lifetime
// constrain.
/// ElementConstrain is a trait that can be made into trait object where
/// the tuple element satisfies.
pub trait ElementSatisfy<ElementConstrain: ?Sized> {
    fn to_constrain_object(&self) -> &ElementConstrain;
    fn to_constrain_object_mut(&mut self) -> &mut ElementConstrain;
}

// Library user don't neet to look beyond this point. Check test mod for usage.

/// Trait on Index, meaning that the element at Index for ConcernedTuple
/// satisfies ElementConstrain.
pub trait OfElementSatisfiesOnTuple<ConcernedTuple, ElementConstrain: ?Sized>:
    TupleIndex + Sized
{
    type ElementType: ElementSatisfy<ElementConstrain> + ?Sized;

    fn getter_for_tuple(
        t: &ConcernedTuple,
    ) -> &dyn TupleGetIndexExt<Self, ElementType = Self::ElementType>;
    fn getter_for_tuple_mut(
        t: &mut ConcernedTuple,
    ) -> &mut dyn TupleGetIndexExt<Self, ElementType = Self::ElementType>;
}

impl<
        Index: TupleIndex,
        ElementConstrain: ElementConstrainMark + ?Sized,
        ElementType: ElementSatisfy<ElementConstrain> + ?Sized,
        ConcernedTuple: TupleGetIndexExt<Self, ElementType = ElementType>,
    > OfElementSatisfiesOnTuple<ConcernedTuple, ElementConstrain> for Index
{
    type ElementType = ElementType;

    fn getter_for_tuple(
        t: &ConcernedTuple,
    ) -> &dyn TupleGetIndexExt<
        Self,
        ElementType = <ConcernedTuple as TupleGetIndexExt<Self>>::ElementType,
    > {
        t
    }

    fn getter_for_tuple_mut(
        t: &mut ConcernedTuple,
    ) -> &mut dyn TupleGetIndexExt<
        Self,
        ElementType = <ConcernedTuple as TupleGetIndexExt<Self>>::ElementType,
    > {
        t
    }
}

/// To make it easy for compiler to compute automated implementation.
pub trait ElementConstrainMark {}

pub struct ElementNoConstrain();
impl ElementConstrainMark for ElementNoConstrain {}

impl<T> ElementSatisfy<ElementNoConstrain> for T {
    fn to_constrain_object(&self) -> &ElementNoConstrain { unreachable!() }

    fn to_constrain_object_mut(&mut self) -> &mut ElementNoConstrain {
        unreachable!()
    }
}

pub trait TupleIndexUpTo<Index: TupleIndex> {}

pub trait TupleIndex: Debug {}

#[macro_use]
mod macros {
    macro_rules! placeholder {
        ($t:ident) => {
            $crate::storage::utils::tuple::placeholders::$t
        };
    }

    macro_rules! make_placeholder {
        ($index:tt) => {
            #[derive(Default, Debug)]
            pub struct $index();

            impl TupleIndex for $index {}

            impl TupleIndexUpTo<$index> for AllPlaceholders {}
        };
    }

    macro_rules! make_placeholders {
        ($($index:tt),*) => {
            $( make_placeholder!{$index} )*

            /// Rust stdlib doesn't derive Default for this many elements.
            #[derive(Default)]
            pub struct AllPlaceholders($(pub placeholder!($index)),*);

            pub const PLACEHOLDERS: AllPlaceholders
                = AllPlaceholders($((placeholder!($index))()),*);
        }
    }

    macro_rules! make_get_index_ext {
        (
            $tuple_type:ty,
            $element_type:ty,
            $place_holder:ty,
            $place_holder_as_field:tt
        ) => {
            impl TupleIndexUpTo<$place_holder> for $tuple_type {}

            impl IndexGetExt<$tuple_type> for $place_holder {
                type ElementType = $element_type;

                fn get_impl<'a>(x: &'a $tuple_type) -> &'a Self::ElementType {
                    &x.$place_holder_as_field
                }

                fn get_mut_impl<'a>(
                    x: &'a mut $tuple_type,
                ) -> &'a mut Self::ElementType {
                    &mut x.$place_holder_as_field
                }
            }

            impl TupleGetIndexExt<$place_holder> for $tuple_type {
                type ElementType = $element_type;

                fn get_impl(&self) -> &Self::ElementType {
                    &self.$place_holder_as_field
                }

                fn get_mut_impl(&mut self) -> &mut Self::ElementType {
                    &mut self.$place_holder_as_field
                }
            }
        };
    }

    macro_rules! make_get_index_ext_all {
        (
            $tuple_struct_name:ident(),
            ($place_holder_max:ty $(, $place_holder_rest:ty)*),
            ($size:tt $(, $place_holder_as_field_rest:tt)*)
        ) => {
            impl TupleIndexExt for $tuple_struct_name {
                type IndexMax = $place_holder_max;

                fn size_tuple() -> usize { $size }

                fn size(&self) -> usize { $size }
            }

            impl TupleIndexUpTo<$place_holder_max> for $tuple_struct_name {}
        };
        (
            $tuple_struct_name:ident($element_type:ty $(, $element_type_rest:ty)*),
            ($place_holder:ty $(, $place_holder_rest:ty)*),
            ($place_holder_as_field:tt $(, $place_holder_as_field_rest:tt)*)
        ) => {
            make_get_index_ext!{
                $tuple_struct_name, $element_type, $place_holder, $place_holder_as_field
            }

            make_get_index_ext_all!{
                $tuple_struct_name($($element_type_rest),*),
                ($($place_holder_rest),*),
                ($($place_holder_as_field_rest),*)
            }
        }
    }

    macro_rules! tuple_from_to_iter_impl {
        (
            (($($place_holder:ty),*) ()),
            (($($place_holder_as_field:tt),*) ())
        ) => {};
        (
            (() ($place_holder_last:ty $(, $place_holder_rest:ty)*)),
            (() ($place_holder_as_field_last:tt $(, $place_holder_as_field_rest:tt)*))
        ) => {
            impl<T: TupleIndexUpTo<$place_holder_last>, ElementConstrain: ElementConstrainMark + ?Sized>
            TupleIterFromTo<$place_holder_last, $place_holder_last, ElementConstrain> for T {
                fn iterate_from_to<F: IterCallFamilyTrait<Self, ElementConstrain>>(mut f: F) {
                    f.prepare_iter();
                    f.finish_iter();
                }
            }

            tuple_from_to_iter_impl!{
                (($place_holder_last) ($($place_holder_rest),*)),
                (($place_holder_as_field_last) ($($place_holder_as_field_rest),*))
            }
        };
        (
            (($place_holder_first:ty $(, $place_holder:ty)*) ($place_holder_last:ty $(, $place_holder_rest:ty)*)),
            (($place_holder_as_field_first:tt $(, $place_holder_as_field:tt)*) ($place_holder_as_field_last:tt $(, $place_holder_as_field_rest:tt)*))
        ) => {
            impl<T: TupleIndexUpTo<$place_holder_last>, ElementConstrain: ElementConstrainMark + ?Sized>
            TupleIterFromTo<
                $place_holder_first, $place_holder_last, ElementConstrain,
            > for T where
                T: TupleGetIndexExt<$place_holder_first>,
                $(T: TupleGetIndexExt<$place_holder>,)*
                $place_holder_first: OfElementSatisfiesOnTuple<T, ElementConstrain>,
                $($place_holder: OfElementSatisfiesOnTuple<T, ElementConstrain>,)*
            {
                fn iterate_from_to<F: IterCallFamilyTrait<Self, ElementConstrain>>(mut f: F) {
                    f.prepare_iter();
                    f.iter_step(&placeholder!(PLACEHOLDERS).$place_holder_as_field_first, $place_holder_as_field_first);
                    $(f.iter_step(&placeholder!(PLACEHOLDERS).$place_holder_as_field, $place_holder_as_field);)*
                    f.finish_iter();
                }
            }

            tuple_from_to_iter_impl!{
                (($place_holder_first, $($place_holder,)* $place_holder_last) ($($place_holder_rest),*)),
                (($place_holder_as_field_first, $($place_holder_as_field,)* $place_holder_as_field_last) ($($place_holder_as_field_rest),*))
            }
        }
    }

    macro_rules! tuple_iter_impl {
        (
            (($($place_holder:ty),*) ()),
            (($($place_holder_as_field:tt),*) ())
        ) => {};
        (
            (() ($place_holder_last:ty $(, $place_holder_rest:ty)*)),
            (() ($place_holder_as_field_last:tt $(, $place_holder_as_field_rest:tt)*))
        ) => {
            tuple_from_to_iter_impl!{
                (() ($place_holder_last, $($place_holder_rest),*)),
                (() ($place_holder_as_field_last, $($place_holder_as_field_rest),*))
            }

            tuple_iter_impl!{
                (($place_holder_last) ($($place_holder_rest),*)),
                (($place_holder_as_field_last) ($($place_holder_as_field_rest),*))
            }
        };
        (
            (($($place_holder:ty),+) ($place_holder_last:ty $(, $place_holder_rest:ty)*)),
            (($($place_holder_as_field:tt),+) ($place_holder_as_field_last:tt $(, $place_holder_as_field_rest:tt)*))
        ) => {
            tuple_from_to_iter_impl!{
                (() ($place_holder_last $(, $place_holder_rest)*)),
                (() ($place_holder_as_field_last $(, $place_holder_as_field_rest)*))
            }

            tuple_iter_impl!{
                (($($place_holder,)* $place_holder_last) ($($place_holder_rest),*)),
                (($($place_holder_as_field,)* $place_holder_as_field_last) ($($place_holder_as_field_rest),*))
            }
        }
    }
}

pub mod placeholders {
    use super::*;

    make_placeholders! {_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13}

    tuple_iter_impl! {
        (() (
            placeholder!(_0), placeholder!(_1), placeholder!(_2),
            placeholder!(_3), placeholder!(_4), placeholder!(_5),
            placeholder!(_6), placeholder!(_7), placeholder!(_8),
            placeholder!(_9), placeholder!(_10), placeholder!(_11),
            placeholder!(_12), placeholder!(_13)
        )),
        (() (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13))
    }
}

//#[cfg(test)]
mod test {
    use super::*;

    make_tuple_with_index_ext!(Test(i32, f64, Vec<u8>, Box<[u8]>));
    make_tuple_with_index_ext!(Test2(f64, Vec<u8>, Box<[u8]>, i32));

    trait ElementIsDebug: Debug {}
    impl ElementConstrainMark for dyn ElementIsDebug {}
    impl ElementIsDebug for i32 {}
    impl ElementIsDebug for f64 {}
    impl ElementIsDebug for Vec<u8> {}
    impl ElementIsDebug for Box<[u8]> {}

    trait ElementToPrint {
        fn to_string(&self) -> String;
    }
    impl ElementConstrainMark for dyn ElementToPrint {}

    impl ElementToPrint for i32 {
        fn to_string(&self) -> String { ToString::to_string(self) }
    }
    impl ElementToPrint for f64 {
        fn to_string(&self) -> String { ToString::to_string(self) }
    }
    impl ElementToPrint for Vec<u8> {
        fn to_string(&self) -> String {
            unsafe { std::str::from_utf8_unchecked(self.as_slice()) }
                .to_string()
        }
    }
    impl ElementToPrint for Box<[u8]> {
        fn to_string(&self) -> String {
            unsafe { std::str::from_utf8_unchecked(self.as_ref()) }.to_string()
        }
    }

    impl<Element: 'static + ElementToPrint> ElementSatisfy<dyn ElementToPrint>
        for Element
    {
        fn to_constrain_object(&self) -> &(dyn 'static + ElementToPrint) {
            self
        }

        fn to_constrain_object_mut(
            &mut self,
        ) -> &mut (dyn 'static + ElementToPrint) {
            self
        }
    }

    impl<Element: 'static + ElementIsDebug> ElementSatisfy<dyn ElementIsDebug>
        for Element
    {
        fn to_constrain_object(&self) -> &(dyn 'static + ElementIsDebug) {
            self
        }

        fn to_constrain_object_mut(
            &mut self,
        ) -> &mut (dyn 'static + ElementIsDebug) {
            self
        }
    }

    #[test]
    fn test() {
        let t = Test(
            11,
            2.3,
            "5 8".into(),
            "13 21".to_string().into_boxed_str().into_boxed_bytes(),
        );

        struct F<'a> {
            t: &'a Test,
        }

        impl IterCallFamilyTrait<Test, dyn ElementToPrint> for F<'_> {
            fn prepare_iter(&mut self) {}

            fn iter_step<
                Index: OfElementSatisfiesOnTuple<Test, dyn ElementToPrint>,
            >(
                &mut self, _placeholder: &'static Index, index: usize,
            ) {
                println!(
                    "Test field {}: {}",
                    index,
                    Index::getter_for_tuple(self.t)
                        .get_impl()
                        .to_constrain_object()
                        .to_string()
                );
            }

            fn finish_iter(&mut self) {}
        }

        Test::iterate(F { t: &t });
        Test::iter_from_to(&PLACEHOLDERS.0, &PLACEHOLDERS.2, F { t: &t });

        struct G<'a> {
            t: &'a Test,
        }

        impl IterCallFamilyTrait<Test, dyn ElementIsDebug> for G<'_> {
            fn prepare_iter(&mut self) {}

            fn iter_step<
                Index: OfElementSatisfiesOnTuple<Test, dyn ElementIsDebug>,
            >(
                &mut self, _placeholder: &'static Index, index: usize,
            ) {
                println!(
                    "Test field {}: {:?}",
                    index,
                    Index::getter_for_tuple(self.t)
                        .get_impl()
                        .to_constrain_object()
                );
            }

            fn finish_iter(&mut self) {}
        }

        Test::iterate(G { t: &t });

        IterCallFamilyTrait::iter_step(&mut F { t: &t }, &PLACEHOLDERS.1, 1);

        #[derive(Default)]
        struct Counter {
            iter_counts: u8,
            finish_called: bool,
        }

        impl IterCallFamilyTrait<Test, ElementNoConstrain> for &mut Counter {
            fn prepare_iter(&mut self) {
                self.iter_counts = 0;
                self.finish_called = false;
            }

            fn iter_step<
                Index: OfElementSatisfiesOnTuple<Test, ElementNoConstrain>,
            >(
                &mut self, _placeholder: &'static Index, _index: usize,
            ) {
                self.iter_counts += 1;
            }

            fn finish_iter(&mut self) { self.finish_called = true; }
        }

        impl Counter {
            fn assert(&self, counts: u8) {
                assert_eq!(self.finish_called, true);
                assert_eq!(self.iter_counts, counts);
            }
        }

        let mut counter = Counter::default();

        Test::iter_from_to(&PLACEHOLDERS.0, &PLACEHOLDERS.0, &mut counter);
        counter.assert(0);
        Test::iter_from_to(&PLACEHOLDERS.0, &PLACEHOLDERS.3, &mut counter);
        counter.assert(3);
        Test::iter_from_to(&PLACEHOLDERS.0, &PLACEHOLDERS.4, &mut counter);
        counter.assert(4);
        Test::iter_from_to(&PLACEHOLDERS.1, &PLACEHOLDERS.1, &mut counter);
        counter.assert(0);
        Test::iter_from_to(&PLACEHOLDERS.1, &PLACEHOLDERS.4, &mut counter);
        counter.assert(3);
        Test::iter_from_to(&PLACEHOLDERS.3, &PLACEHOLDERS.3, &mut counter);
        counter.assert(0);
        Test::iter_from_to(&PLACEHOLDERS.3, &PLACEHOLDERS.4, &mut counter);
        counter.assert(1);
        Test::iter_from_to(&PLACEHOLDERS.4, &PLACEHOLDERS.4, &mut counter);
        counter.assert(0);

        println!("Test total fields {}", Test::size_tuple());

        let t2 = Test2(
            t.get::<placeholders::_1>().clone(),
            t.get::<placeholders::_2>().clone(),
            t.get::<placeholders::_3>().clone(),
            t.get::<placeholders::_0>().clone(),
        );

        assert_eq!(*t2.get::<placeholder!(_0)>(), 2.3);
        assert_eq!(*t2.get::<placeholder!(_1)>(), "5 8".as_bytes());
        assert_eq!(&**t2.get::<placeholder!(_2)>(), "13 21".as_bytes());
        assert_eq!(*t2.get::<placeholder!(_3)>(), 11);
    }
}

use std::fmt::Debug;
