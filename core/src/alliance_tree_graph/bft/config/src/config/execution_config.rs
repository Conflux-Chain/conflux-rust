// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{config::RootPath, utils};
use anyhow::Result;
use libra_types::{
    contract_event::ContractEvent,
    crypto_proxies::ValidatorSet,
    language_storage::TypeTag,
    transaction::{ChangeSet, Transaction},
    write_set::WriteSet,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

const GENESIS_DEFAULT: &str = "genesis.blob";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionConfig {
    pub address: String,
    pub port: u16,
    #[serde(skip)]
    pub genesis: Option<Transaction>,
    pub genesis_file_location: PathBuf,
}

impl Default for ExecutionConfig {
    fn default() -> ExecutionConfig {
        ExecutionConfig {
            address: "localhost".to_string(),
            port: 6183,
            genesis: None,
            genesis_file_location: PathBuf::new(),
        }
    }
}

impl ExecutionConfig {
    pub fn load(
        &mut self, root_dir: &RootPath, validator_set: ValidatorSet,
    ) -> Result<()> {
        if !self.genesis_file_location.as_os_str().is_empty() {
            let path = root_dir.full_path(&self.genesis_file_location);
            let mut file = File::open(&path)?;
            let mut buffer = vec![];
            file.read_to_end(&mut buffer)?;
            // TODO: update to use `Transaction::WriteSet` variant when ready.
            self.genesis = Some(lcs::from_bytes(&buffer)?);
        } else {
            let event_data = lcs::to_bytes(&validator_set)?;
            let event = ContractEvent::new(
                ValidatorSet::change_event_key(),
                0, /* sequence_number */
                TypeTag::ByteArray,
                event_data,
            );

            let change_set = ChangeSet::new(WriteSet::default(), vec![event]);
            let transaction = Transaction::WriteSet(change_set);
            self.genesis = Some(transaction);
        }

        Ok(())
    }

    pub fn save(&mut self, root_dir: &RootPath) -> Result<()> {
        if let Some(genesis) = &self.genesis {
            if self.genesis_file_location.as_os_str().is_empty() {
                self.genesis_file_location = PathBuf::from(GENESIS_DEFAULT);
            }
            let path = root_dir.full_path(&self.genesis_file_location);
            let mut file = File::create(&path)?;
            file.write_all(&lcs::to_bytes(&genesis)?)?;
        }
        Ok(())
    }

    pub fn randomize_ports(&mut self) {
        self.port = utils::get_available_port();
    }
}
