pub mod storage_dir {
    use std::path::PathBuf;

    lazy_static! {
        pub static ref STORAGE_DIR: PathBuf = "storage_db".into();
    }
}

pub mod storage_manager {
    use std::path::{Path, PathBuf};

    pub struct StorageConfiguration {
        pub snapshot_epoch_count: u32,
        pub public_params_dir: PathBuf,
        pub path_storage_dir: PathBuf,
        pub shard_size: Option<usize>,
    }
}
