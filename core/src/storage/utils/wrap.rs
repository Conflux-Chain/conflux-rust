// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// This trait is designed for associated type in trait, such as iterator,
/// where the type could be a borrow of self, or an independent type.
///
/// It's difficult to offer generic trait methods implementation for all
/// variants. One possible way is to use HRTB, however under some cases we
/// could only implement '_ or have implementation for '_ instead of
/// for<'any>, especially when we have no control over third-party code,
/// which render some usages infeasible.
///
/// Say if we have the code below:
///
/// trait LifetimeBoundedTrait<'a> {
///     fn get(&'a mut self) -> T<'a>;
/// }
///
/// #[derive(Debug)]
/// struct T<'a> {
///    s: &'a i64,
/// }
///
/// struct EndUserType<TypeImplTrait> {
///     v: TypeImplTrait,
/// }
///
/// impl<T> EndUserType<T> where for<'a> T: LifetimeBoundedTrait<'a> {
///     fn use_t(&mut self) {
///         let ret = self.v.get();
///         println!("{:?}", ret);
///     }
/// }
///
/// struct ConcreteType {}
///
/// impl<'a> LifetimeBoundedTrait<'a> for ConcreteType {
///     fn get(&'a mut self) -> T<'a> { T{s: &0} }
/// }
///
/// impl<'a: 'b, 'b> LifetimeBoundedTrait<'b> for &'a mut ConcreteType {
///     fn get(&'b mut self) -> T<'b> { (*self).get() }
/// }
///
/// Ideally, we could store &mut ConcreteType in EndUserType#use_t in the
/// same way. But It's not possible for the EndUserType to store &mut
/// ConcreteType as v, because &mut ConcreteType only implements
/// LifetimeBoundedTrait for '_, not for any lifetime.
///
/// What we have to do, is to drop the lifetime bound for 'a, which is
/// counter-intuitive but works.
///
/// impl<'a, 'b> LifetimeBoundedTrait<'b> for &'a mut ConcreteType {
///     fn get(&'b mut self) -> T<'b> { (*self).get() }
/// }
///
/// In some other cases, with &'x F, rust requires F: 'x in generic type
/// constrain, which may be harder to workaround for HRTB.

// TODO: Implement, to have a proper iterator. Otherwise delete this file at
// clean up.

/*
// FIXME: we should separate Borrowed 'a and Owned for better rust borrow checking deduction.
pub trait WrappedBorrowMarker {
    type Borrowed;
    type Owned;
}
pub struct WrapBorrowedMarker {}
impl WrappedBorrowMarker for WrapBorrowedMarker {
    type Borrowed = ();
    type Owned = !;
}
pub struct WrapOwnedMarker {}
impl WrappedBorrowMarker for WrapOwnedMarker {
    type Borrowed = !;
    type Owned = ();
}
*/

pub trait WrappedLifetimeFamily<'a> {
    type Out: 'a;
}

pub trait WrappedTrait: for<'a> WrappedLifetimeFamily<'a> {
    //type BorrowMarker: WrappedBorrowMarker;
}

/*
pub enum Wrap<'a, Wrapped: WrappedTrait>{
    Borrowed(<Wrapped as WrappedLifetimeFamily<'a>>::Out, Wrapped::BorrowMarker::Borrowed),
    Owned(<Wrapped as WrappedLifetimeFamily<'a>>::Out, Wrapped::BorrowMarker::Owned),
}
*/

pub struct Wrap<'a, Wrapped: ?Sized + WrappedTrait>(
    pub <Wrapped as WrappedLifetimeFamily<'a>>::Out,
);

impl<'a, Wrapped: ?Sized + WrappedTrait> Wrap<'a, Wrapped> {
    pub fn take(self) -> <Wrapped as WrappedLifetimeFamily<'a>>::Out { self.0 }
}

pub trait LaterLifetime<'a, 'b, Wrapped: ?Sized> {
    type Longest: 'b;
}

impl<'a, 'b: 'a, Wrapped: ?Sized + WrappedTrait> LaterLifetime<'a, 'b, Wrapped>
    for Wrapped
{
    type Longest = <Wrapped as WrappedLifetimeFamily<'b>>::Out;
}

pub trait AllLaterLifetime<'b, Wrapped: ?Sized>:
    for<'a> LaterLifetime<'a, 'b, Wrapped>
{
    type T: 'b;
}
