use cfx_types::parse_hex_string;
use clap::{ArgMatches, Args};
use client::{
    configuration::Configuration,
    state_dump::{dump_whole_state, iterate_dump_whole_state, StateDumpConfig},
};
use parking_lot::{Condvar, Mutex};
use serde_json;
use std::{collections::HashMap, fs, path::Path, sync::Arc};

#[derive(Args, Debug)]
pub struct DumpCommand {
    /// Include accounts for which we don't have the address (missing preimage)
    // #[arg(id = "incompletes", long = "incompletes")]
    // incompletes: bool,
    /// Print streaming JSON iteratively, delimited by newlines
    // #[arg(id = "iterative", long = "iterative", default_value = "true")]
    // iterative: bool,
    /// Max number of elements (0 = no limit)
    #[arg(
        id = "limit",
        long = "limit",
        value_name = "NUM",
        default_value = "0"
    )]
    limit: u64,
    /// Target block number, if not specified, the latest block will be used
    #[arg(id = "block", long = "block", value_name = "NUM")]
    block: Option<u64>,
    /// Exclude contract code (save db lookups)
    #[arg(id = "nocode", long = "nocode")]
    no_code: bool,
    /// Exclude storage entries (save db lookups)
    #[arg(id = "nostorage", long = "nostorage")]
    no_storage: bool,
    /// Start position address
    #[arg(
        id = "start",
        long = "start",
        value_name = "String",
        default_value = "0x0000000000000000000000000000000000000000"
    )]
    start: String,
    /// Path to the output folder (default: ./dump)
    #[arg(id = "output", long = "output", value_name = "PATH")]
    output: Option<String>,
    /// Multi file mode
    #[arg(id = "multifile", long = "multifile")]
    multi_file: bool,
}

impl DumpCommand {
    pub fn parse(matches: &ArgMatches) -> Result<Self, String> {
        let output = matches.get_one::<String>("output").cloned();
        Ok(Self {
            block: matches.get_one::<u64>("block").cloned(),
            // incompletes: matches.get_flag("incompletes"),
            // iterative: matches.get_flag("iterative"),
            limit: matches.get_one::<u64>("limit").cloned().unwrap_or(0),
            no_code: matches.get_flag("nocode"),
            no_storage: matches.get_flag("nostorage"),
            start: matches.get_one::<String>("start").cloned().unwrap_or(
                "0x0000000000000000000000000000000000000000".to_string(),
            ),
            output,
            multi_file: matches.get_flag("multifile"),
        })
    }

    fn get_state_dump_config(
        &self, output_path: &str,
    ) -> Result<StateDumpConfig, String> {
        let start_address = parse_hex_string(&self.start)
            .map_err(|e| format!("Invalid address: {}", e))?;
        Ok(StateDumpConfig {
            start_address,
            limit: self.limit,
            block: self.block,
            no_code: self.no_code,
            no_storage: self.no_storage,
            out_put_path: output_path.to_string(),
        })
    }

    pub fn execute(&self, conf: &mut Configuration) -> Result<String, String> {
        // Determine output directory
        let output_path = match self.output {
            Some(ref path) => path,
            None => {
                "./dump" // Default to "./dump" if no output specified
            }
        };

        // Ensure the directory exists
        if !Path::new(output_path).exists() {
            fs::create_dir_all(output_path).map_err(|e| {
                format!("Failed to create output directory: {}", e)
            })?;
        }

        let exit = Arc::new((Mutex::new(false), Condvar::new()));
        let config = self.get_state_dump_config(output_path)?;

        let _total_accounts = if self.multi_file {
            // Write to multiple files
            let state_root = iterate_dump_whole_state(
                conf,
                exit,
                &config,
                |account_state| {
                    let address =
                        account_state.address.expect("address is not set");
                    let filename = format!("{:?}.json", address);
                    let file_path = Path::new(output_path).join(&filename);

                    // Serialize account_state to JSON
                    let json_content =
                        serde_json::to_string_pretty(&account_state)
                            .map_err(|e| {
                                format!(
                            "Failed to serialize account state for {}: {}",
                            address, e
                        )
                            })
                            .expect("Failed to serialize account state");

                    // Write to file
                    fs::write(&file_path, json_content)
                        .map_err(|e| {
                            format!(
                                "Failed to write file {}: {}",
                                file_path.display(),
                                e
                            )
                        })
                        .expect("Failed to write file");
                },
            )?;

            // Write meta info
            let mut meta_info = HashMap::new();
            meta_info.insert("root".to_string(), state_root);
            let meta_file_path = Path::new(output_path).join("meta.json");
            let meta_content = serde_json::to_string_pretty(&meta_info)
                .map_err(|e| format!("Failed to serialize state: {}", e))?;
            fs::write(&meta_file_path, meta_content)
                .map_err(|e| format!("Failed to write meta file: {}", e))?;
            0
        } else {
            let state = dump_whole_state(conf, exit, &config)?;
            let total_accounts = state.accounts.len();
            // Write to a single file
            let file_path = Path::new(output_path).join("state.json");
            let json_content = serde_json::to_string_pretty(&state)
                .map_err(|e| format!("Failed to serialize state: {}", e))?;
            fs::write(&file_path, json_content).map_err(|e| {
                format!("Failed to write file {}: {}", file_path.display(), e)
            })?;
            total_accounts
        };

        Ok(format!(
            "Dumped account state to output directory: {}",
            output_path
        ))
    }
}
