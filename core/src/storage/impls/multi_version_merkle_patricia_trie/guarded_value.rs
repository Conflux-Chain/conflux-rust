// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::ops::{Deref, DerefMut};

/// To prevent automatic copy from leaking guarded value.
/// Please always wrap the value with NonCopy if the value is Copy
/// otherwise it's so easy to accidentally copy without notice,
/// e.g. in matching arms, if let clauses.
#[derive(Clone)]
pub struct NonCopy<T: ?Sized>(pub T);

pub struct GuardedValue<GuardType, ValueType> {
    guard: GuardType,
    value: ValueType,
}

impl<GuardType, ValueType> GuardedValue<GuardType, ValueType> {
    pub fn new(guard: GuardType, value: ValueType) -> Self {
        Self { guard, value }
    }

    // FIXME: mark it unsafe?
    /// It's unsafe because user may be able to drop the guard but use the value
    /// later. Extra care is needed when using this method.
    pub fn into(self) -> (GuardType, ValueType) { (self.guard, self.value) }
}

impl<'a, GuardType: 'a + Deref<Target = TargetType>, TargetType>
    GuardedValue<GuardType, NonCopy<&'a TargetType>>
{
    pub fn new_derefed(guard: GuardType) -> Self {
        let derefed: *const TargetType = &*guard;
        Self {
            guard,
            value: NonCopy(unsafe { &*derefed } as &'a TargetType),
        }
    }
}

impl<'a, GuardType: 'a + DerefMut<Target = TargetType>, TargetType>
    GuardedValue<GuardType, &'a mut TargetType>
{
    pub fn new_derefed_mut(mut guard: GuardType) -> Self {
        let derefed_mut: *mut TargetType = &mut *guard;
        Self {
            guard,
            value: unsafe { &mut *derefed_mut } as &'a mut TargetType,
        }
    }
}

impl<GuardType, ValueType: Clone> GuardedValue<GuardType, ValueType> {
    /// Unsafe because the lock guard is released.
    /// There is no guarantee for the validity of value especially when
    /// ValueType is reference alike, e.g. an index.
    pub unsafe fn get_value(&self) -> ValueType { self.value.clone() }
}

impl<GuardType, ValueType> AsRef<ValueType>
    for GuardedValue<GuardType, ValueType>
{
    fn as_ref(&self) -> &ValueType { &self.value }
}

impl<GuardType, ValueType> AsMut<ValueType>
    for GuardedValue<GuardType, ValueType>
{
    fn as_mut(&mut self) -> &mut ValueType { &mut self.value }
}

// FIXME: The commented code below seems to be used by Cow... Check the usage
// FIXME: again and see if we can use new_derefed, and also check if we can
// FIXME: remove as_ref / as_mut.
/*
impl<GuardType, ValueType: Deref> Deref for GuardedValue<GuardType, ValueType> {
    type Target = ValueType::Target;

    fn deref(&self) -> &Self::Target { self.value.deref() }
}

impl<GuardType, ValueType: DerefMut> DerefMut
    for GuardedValue<GuardType, ValueType>
{
    fn deref_mut(&mut self) -> &mut Self::Target { self.value.deref_mut() }
}
*/

impl<GuardType, ValueType> Deref for GuardedValue<GuardType, ValueType> {
    type Target = ValueType;

    fn deref(&self) -> &Self::Target { &self.value }
}

impl<GuardType, ValueType> DerefMut for GuardedValue<GuardType, ValueType> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.value }
}

impl<T: ?Sized> Deref for NonCopy<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl<T: ?Sized> DerefMut for NonCopy<T> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}
