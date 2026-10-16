# serde_yaml compatibility adapter

Published log4rs 1.4 uses `serde_yaml` 0.9, which depends on the archived
`unsafe-libyaml` crate. This unpublished adapter satisfies that version range
and re-exports `yaml_serde`, maintained by the YAML Organization. Its backend
is the maintained `libyaml-rs` fork; it is not a claim that the parser contains
no unsafe Rust.

Root and standalone tool workspaces patch `serde_yaml` to this adapter. PoS
configuration uses the same `yaml_serde` version directly. No logging loader,
refresh thread, configuration format, or advisory exception is introduced.
Remove the adapter and all three patches when a published log4rs release uses
a maintained YAML dependency directly.
