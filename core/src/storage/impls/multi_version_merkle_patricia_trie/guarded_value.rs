// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::ops::{Deref, DerefMut};

pub struct GuardedValue<GuardType, ValueType> {
    guard: GuardType,
    value: ValueType,
}

impl<GuardType, ValueType> GuardedValue<GuardType, ValueType> {
    pub fn new(guard: GuardType, value: ValueType) -> Self {
        Self { guard, value }
    }

    /// Not yet useful but defined for completeness.
    pub fn new_with_fn<F: FnOnce(&GuardType) -> ValueType>(
        _guard: GuardType, _f: F,
    ) -> Self {
        unimplemented!()
    }

    pub fn into(self) -> (GuardType, ValueType) { (self.guard, self.value) }
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

impl<GuardType, ValueType: Deref> Deref for GuardedValue<GuardType, ValueType> {
    type Target = ValueType::Target;

    fn deref(&self) -> &Self::Target { self.value.deref() }
}

impl<GuardType, ValueType: DerefMut> DerefMut
    for GuardedValue<GuardType, ValueType>
{
    fn deref_mut(&mut self) -> &mut Self::Target { self.value.deref_mut() }
}
