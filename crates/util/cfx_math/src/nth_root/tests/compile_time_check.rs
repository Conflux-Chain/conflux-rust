use super::{RootDegree, RootInvParams};
use static_assertions::{assert_impl_all, assert_not_impl_all};
use typenum::{U0, U1, U10, U11, U12, U13, U16, U2, U20, U42, U5};

assert_not_impl_all!(U0: RootDegree);
assert_not_impl_all!(U1: RootDegree);
assert_impl_all!(U2: RootDegree);
assert_impl_all!(U5: RootDegree);
assert_impl_all!(U12: RootDegree);
assert_not_impl_all!(U13: RootDegree);

assert_impl_all!((U2, U16): RootInvParams);
assert_impl_all!((U10, U16): RootInvParams);
assert_impl_all!((U11, U20): RootInvParams);
assert_not_impl_all!((U12, U42): RootInvParams);
