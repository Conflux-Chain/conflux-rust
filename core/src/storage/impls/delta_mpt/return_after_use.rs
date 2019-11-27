// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::mem::swap;

/// While mutable references can only be passed around as method parameters,
/// ReturnAfterUse can pass mutable object in classes.
pub struct ReturnAfterUse<'a, T: 'a> {
    origin: Option<&'a mut Option<T>>,
    current: Option<T>,
}

impl<'a, T: Default> Default for ReturnAfterUse<'a, T> {
    fn default() -> Self {
        Self {
            origin: None,
            current: Some(T::default()),
        }
    }
}

impl<'a, T> Drop for ReturnAfterUse<'a, T> {
    fn drop(&mut self) {
        match &mut self.origin {
            Some(origin_mut) => swap(*origin_mut, &mut self.current),
            None => {}
        }
    }
}

impl<'a, T> ReturnAfterUse<'a, T> {
    pub fn new_from_value(val: T) -> Self {
        Self {
            origin: None,
            current: Some(val),
        }
    }

    pub fn new(option: &'a mut Option<T>) -> Self {
        let mut ret = Self {
            origin: None,
            current: None,
        };
        swap(&mut ret.current, option);
        ret.origin = Some(option);

        ret
    }

    pub fn new_from_origin<'b: 'a>(
        origin: &'a mut ReturnAfterUse<'b, T>,
    ) -> ReturnAfterUse<'a, T> {
        Self::new(&mut origin.current)
    }

    pub fn get_ref(&self) -> &T { return self.current.as_ref().unwrap(); }

    pub fn get_mut(&mut self) -> &mut T {
        return self.current.as_mut().unwrap();
    }
}
