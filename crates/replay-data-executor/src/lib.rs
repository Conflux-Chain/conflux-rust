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

// The `.cfxpack` wire format (packet/codec/decode/verify) lives in the shared
// `cfxpack` crate, used directly at each call site. The oracle workspace
// `[patch]`es cfxpack's conflux deps onto its own crates so the `primitives`
// types it embeds unify with this crate's.
#[cfg(feature = "backend-minimal-mpt")]
pub use cfx_replay_checkpoint as checkpoint;
#[cfg(feature = "backend-minimal-mpt")]
pub mod minimal_backend;
pub mod consensus;
pub mod driver;
mod report;
