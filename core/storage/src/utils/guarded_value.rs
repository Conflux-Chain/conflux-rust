// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: find a better place for this file.

use std::ops::{Deref, DerefMut};

/// To prevent automatic copy from leaking guarded value.
/// Please always wrap the value with NonCopy if the value is Copy
/// otherwise it's so easy to accidentally copy without notice,
/// e.g. in matching arms, if let clauses.
#[derive(Clone)]
pub struct NonCopy<T: ?Sized>(pub T);

/// Please read all comments in this file to prevent leaking of guarded value by
/// accident.
pub struct GuardedValue<GuardType, ValueType> {
    guard: GuardType,
    value: ValueType,
}

impl<GuardType, ValueType> GuardedValue<GuardType, ValueType> {
    pub fn new(guard: GuardType, value: ValueType) -> Self {
        Self { guard, value }
    }

    /// It's unsafe to drop the returned guard manually, or to clone the
    /// ValueType. Extra care is needed when using this method.
    pub fn into(self) -> (GuardType, ValueType) {
        (self.guard, self.value)
    }
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

impl<GuardType, ValueType> AsRef<ValueType>
    for GuardedValue<GuardType, ValueType>
{
    fn as_ref(&self) -> &ValueType {
        &self.value
    }
}

impl<GuardType, ValueType> AsMut<ValueType>
    for GuardedValue<GuardType, ValueType>
{
    fn as_mut(&mut self) -> &mut ValueType {
        &mut self.value
    }
}

/// It's safer to directly deref to the next level target, because when the
/// ValueType is &'a Target, when we deref twice, we get &'a Target, when we
/// deref to the next level we always get the expected &'_ Target.
impl<GuardType, ValueType: Deref> Deref for GuardedValue<GuardType, ValueType> {
    type Target = ValueType::Target;

    fn deref(&self) -> &Self::Target {
        self.value.deref()
    }
}

impl<GuardType, ValueType: DerefMut> DerefMut
    for GuardedValue<GuardType, ValueType>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value.deref_mut()
    }
}

/// Ideally, we should also deref to the next level like above. However, there
/// can be GuardedValue like Option<&'a Target>, for which we can't really do
/// anything more, unless we introduce concept like lifetime coercion classes.
///
/// The goal for all implementations here is to make it hard enough to do
/// something wrong by accident, but still keep it simple.
impl<T: ?Sized> Deref for NonCopy<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for NonCopy<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
