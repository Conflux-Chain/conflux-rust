//! Construction and persistence: build the executor (machine + genesis), seed
//! the minimal-mpt backend from the genesis dump, and export/restore the
//! resumable checkpoint.

use super::{EpochCommitment, Config, Replayer};
use anyhow::{anyhow, Context, Result};
use cfx_config::Configuration;
use cfx_executor::machine::{Machine, VmFactory};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_parameters::genesis::GENESIS_ACCOUNT_ADDRESS;
use cfx_storage::{StateIndex, StorageManager, StorageManagerTrait};
use cfx_types::U256;
use cfxcore::{
    genesis_block::{self, genesis_block},
    NodeType,
};
use clap::{Arg, ArgAction, Command};
use std::{collections::BTreeMap, sync::Arc};

impl Replayer {
    pub fn new(config: Config) -> Result<Self> {
        let config_path = config
            .config_path
            .to_str()
            .ok_or_else(|| anyhow!("config path is not valid UTF-8"))?;
        let mut conf = parse_configuration(config_path)
            .map_err(|e| anyhow!("load config: {e}"))?;

        let temp_dir =
            tempfile::tempdir().context("create replay temp state dir")?;
        conf.raw_conf.conflux_data_dir =
            temp_dir.path().to_string_lossy().into_owned();

        let vm = VmFactory::new(1024 * 32);
        let machine =
            Arc::new(Machine::new_with_builtin(conf.common_params(), vm));
        let storage_manager = Arc::new(
            StorageManager::new(conf.storage_config(&NodeType::Archive))
                .context("initialize replay storage manager")?,
        );

        let genesis_accounts =
            genesis_block::default(conf.is_test_or_dev_mode());
        let genesis = genesis_block(
            &storage_manager,
            genesis_accounts,
            GENESIS_ACCOUNT_ADDRESS,
            U256::zero(),
            machine.clone(),
            conf.raw_conf.execute_genesis,
            conf.raw_conf.chain_id,
            &None,
        );
        storage_manager.notify_genesis_hash(genesis.hash());
        let previous_epoch_hash = genesis.hash();
        let genesis_commitment = EpochCommitment {
            state_root: *genesis.block_header.deferred_state_root(),
            receipts_root: *genesis.block_header.deferred_receipts_root(),
            logs_bloom_hash: *genesis.block_header.deferred_logs_bloom_hash(),
        };
        // `mut` is only consumed by the genesis dump under the minimal-mpt
        // backend below; the default backend only reads the state root.
        #[cfg_attr(not(feature = "backend-minimal-mpt"), allow(unused_mut))]
        let mut genesis_state = storage_manager
            .get_state_no_commit(
                StateIndex::new_for_readonly(
                    &previous_epoch_hash,
                    &StateRootWithAuxInfo::genesis(&previous_epoch_hash),
                ),
                false,
                None,
            )
            .context("open genesis state")?
            .ok_or_else(|| anyhow!("genesis state missing"))?;
        let previous_state_root = genesis_state
            .get_state_root()
            .context("read genesis state root")?;
        // Seed the minimal-mpt backend with the genesis state. The whole
        // genesis lives in the delta trie at this point, so reading with an
        // empty address prefix dumps every genesis key/value (both spaces) in
        // canonical form. They are loaded into the delta uncommitted (height
        // stays 0), matching where the real backend keeps genesis until the
        // first snapshot boundary.
        #[cfg(feature = "backend-minimal-mpt")]
        let minimal_backend = {
            let genesis_kvs = genesis_state
                .read_all(
                    primitives::StorageKey::AddressPrefixKey(b"")
                        .with_native_space(),
                )
                .map_err(|e| anyhow!("dump genesis state: {e}"))?
                .unwrap_or_default();
            crate::minimal_backend::MinimalBackend::from_genesis_kvs(
                genesis_kvs,
            )
            .map_err(|e| anyhow!("seed minimal backend genesis: {e}"))?
        };
        let snapshot_epoch_count = conf
            .storage_config(&NodeType::Archive)
            .consensus_param
            .snapshot_epoch_count;

        Ok(Self {
            conf,
            _temp_dir: Some(temp_dir),
            storage_manager,
            machine,
            snapshot_epoch_count,
            previous_epoch_hash,
            previous_state_root,
            commitments_by_height: BTreeMap::from([(0, genesis_commitment)]),
            executed_epochs_by_height: BTreeMap::new(),
            #[cfg(feature = "backend-minimal-mpt")]
            minimal_backend,
        })
    }

    /// Committed height so far (`== last pivot height`, 0 before any epoch).
    /// Lets the driver know where a resumed run picks up.
    #[cfg(feature = "backend-minimal-mpt")]
    pub fn committed_height(&self) -> u64 {
        self.minimal_backend.height()
    }

    /// Capture a resumable checkpoint at the current (boundary) height. The
    /// trie half reuses minimal-mpt's `PersistedState`; the executor windows
    /// (`commitments_by_height`, `executed_epochs_by_height`) and the
    /// `previous_*` cursor are carried alongside. See [`crate::checkpoint`].
    #[cfg(feature = "backend-minimal-mpt")]
    pub fn export_checkpoint(&self) -> crate::checkpoint::Checkpoint {
        crate::checkpoint::Checkpoint::build(
            self.minimal_backend.export_persisted(),
            self.previous_epoch_hash,
            &self.previous_state_root,
            &self.commitments_by_height,
            &self.executed_epochs_by_height,
        )
    }

    /// Rebuild an executor positioned exactly at a checkpoint. Genesis and the
    /// machine are reconstructed by `new`, then the minimal-mpt state and the
    /// executor windows are overwritten from the checkpoint, so execution
    /// continues from the checkpoint height as if it had never stopped.
    #[cfg(feature = "backend-minimal-mpt")]
    pub fn restore(
        config: Config,
        checkpoint: crate::checkpoint::Checkpoint,
    ) -> Result<Self> {
        let mut executor = Self::new(config)?;
        let (mmpt, prev_hash, prev_root, commitments, executed) =
            checkpoint.into_parts()?;
        executor.minimal_backend =
            crate::minimal_backend::MinimalBackend::from_persisted(mmpt);
        executor.previous_epoch_hash = prev_hash;
        executor.previous_state_root = prev_root;
        executor.commitments_by_height = commitments;
        executor.executed_epochs_by_height = executed;
        Ok(executor)
    }
}

fn parse_configuration(config_path: &str) -> Result<Configuration, String> {
    let matches = Command::new("cfx-replay-exec-config")
        .arg(Arg::new("config").long("config").num_args(1))
        .arg(
            Arg::new("archive")
                .long("archive")
                .action(ArgAction::SetTrue),
        )
        .arg(Arg::new("full").long("full").action(ArgAction::SetTrue))
        .arg(Arg::new("light").long("light").action(ArgAction::SetTrue))
        .try_get_matches_from([
            "cfx-replay-exec-config",
            "--config",
            config_path,
        ])
        .map_err(|e| e.to_string())?;
    Configuration::parse(&matches)
}
