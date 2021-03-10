// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Unlike shared_ptr in C++, rust's Arc isn't flexible enough and didn't make
/// full use of the shared ptr design and implementation.
///
/// There are two main features missing:
/// 1. shared_from_this / enable_shared_from_this. Create shared ptr from
/// reference to this.
/// 2. Being able to share refcount with a shared ptr of different type, which
/// is usually used to pass the shared ptr of base class or class fields around.
///
/// Doing so for rust isn't as simple/safe as C++ due to rust design.
pub struct ArcMapped<OriginT: ?Sized, T: ?Sized> {
    origin: Arc<OriginT>,
    ptr: *const T,
}

unsafe impl<OriginT: ?Sized, T: ?Sized> Send for ArcMapped<OriginT, T> {}
unsafe impl<OriginT: ?Sized, T: ?Sized> Sync for ArcMapped<OriginT, T> {}

impl<OriginT: ?Sized, T: ?Sized> Clone for ArcMapped<OriginT, T> {
    fn clone(&self) -> Self {
        Self {
            origin: self.origin.clone(),
            ptr: self.ptr,
        }
    }
}

impl<OriginT: ?Sized, T: ?Sized> ArcMapped<OriginT, T> {
    pub fn new(origin: Arc<OriginT>, ptr: *const T) -> Self {
        Self { origin, ptr }
    }

    pub fn into_arc(self) -> Arc<OriginT> {
        self.origin
    }

    pub fn ref_arc(&self) -> &Arc<OriginT> {
        &self.origin
    }
}

impl<OriginT: ?Sized, T: ?Sized> Deref for ArcMapped<OriginT, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr }
    }
}

/// Only use this function on object which is already managed by an Arc.
pub unsafe fn shared_from_this<T: ?Sized>(t: *const T) -> Arc<T> {
    let temp = Arc::from_raw(t);
    let cloned = temp.clone();
    Arc::into_raw(temp);
    cloned
}

use std::{ops::Deref, sync::Arc};
