pub mod storage_manager {
    pub struct StorageConfiguration {
        pub conflux_data_dir: String,
        pub snapshot_epoch_count: u32,
    }

    impl StorageConfiguration {
        pub fn new_default(
            conflux_data_dir: &str, snapshot_epoch_count: u32,
        ) -> Self {
            Self {
                conflux_data_dir: conflux_data_dir.into(),
                snapshot_epoch_count,
            }
        }
    }
}
