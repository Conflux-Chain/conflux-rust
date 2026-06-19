// Exactly one state-trie backend is active, selected by a cargo feature.
#[cfg(all(feature = "backend-cfx-storage", feature = "backend-minimal-mpt"))]
compile_error!(
    "features `backend-cfx-storage` and `backend-minimal-mpt` are mutually \
     exclusive; build the minimal backend with \
     `--no-default-features --features backend-minimal-mpt`"
);
#[cfg(not(any(feature = "backend-cfx-storage", feature = "backend-minimal-mpt")))]
compile_error!(
    "no state-trie backend selected; enable `backend-cfx-storage` (default) \
     or `backend-minimal-mpt`"
);

pub mod codec;
pub mod decode;
#[cfg(feature = "backend-minimal-mpt")]
pub mod minimal_backend;
pub mod packet;
pub mod replay_exec;
pub mod verify;
