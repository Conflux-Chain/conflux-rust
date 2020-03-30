// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// macro for reducing boilerplate for unsupported methods
#[macro_use]
macro_rules! not_supported {
    () => {};
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> BoxFuture<$ret:ty> )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> BoxFuture<$ret> )? {
            use jsonrpc_core::futures::future::{Future, IntoFuture};
            Err(RpcError::method_not_found())
                .into_future()
                .boxed()
        }

        not_supported!($($tail)*);
    };
    ( fn $fn:ident ( &self $(, $name:ident : $type:ty)* ) $( -> $ret:ty )? ; $($tail:tt)* ) => {
        #[allow(unused_variables)]
        fn $fn ( &self $(, $name : $type)* ) $( -> $ret )? {
            Err(RpcError::method_not_found())
        }

        not_supported!($($tail)*);
    };
}

pub mod cfx;
pub mod common;
pub mod light;
pub mod pubsub;
