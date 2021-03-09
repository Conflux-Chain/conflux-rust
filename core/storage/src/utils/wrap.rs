// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::utils::tuple::ElementSatisfy;

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

pub trait WrappedLifetimeFamily<'a, Constrain: ?Sized> {
    type Out: 'a + Sized + ElementSatisfy<Constrain>;
}

pub trait WrappedTrait<Constrain: ?Sized>:
    for<'a> WrappedLifetimeFamily<'a, Constrain>
// This is unnecessary and troublesome since rustc 1.49.0.
//where for<'a> <Self as WrappedLifetimeFamily<'a, Constrain>>::Out: Sized
{
}

pub struct Wrap<
    'a,
    Wrapped: ?Sized + WrappedTrait<Constrain>,
    Constrain: ?Sized,
>(pub <Wrapped as WrappedLifetimeFamily<'a, Constrain>>::Out);

impl<'a, Wrapped: ?Sized + WrappedTrait<Constrain>, Constrain: ?Sized>
    Wrap<'a, Wrapped, Constrain>
{
    pub fn take(
        self,
    ) -> <Wrapped as WrappedLifetimeFamily<'a, Constrain>>::Out {
        self.0
    }
}
