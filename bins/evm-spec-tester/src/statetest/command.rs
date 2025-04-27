use cfx_config::{Configuration, RawConfiguration};
use primitives::block_header::CIP112_TRANSITION_HEIGHT;
use std::path::PathBuf;
use structopt::StructOpt;

/// ethereum statetest doc: https://eest.ethereum.org/main/consuming_tests/state_test/
#[derive(StructOpt)]
#[structopt(name = "statetest", about = "State test command")]
pub struct StateTestCmd {
    /// Paths to test files or directories
    #[structopt(parse(from_os_str), required = true)]
    pub(super) paths: Vec<PathBuf>,

    /// Configuration file path
    #[structopt(short, long, parse(try_from_str = make_configuration), required = true, help = "Path to the configuration file")]
    pub(super) config: Configuration,

    /// Only run tests matching this string
    #[structopt(short, long)]
    pub(super) matches: Option<String>,

    /// Verbosity level (can be used multiple times)
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,
}

fn make_configuration(config_file: &str) -> Result<Configuration, String> {
    let mut config = Configuration::default();
    config.raw_conf = RawConfiguration::from_file(config_file)?;

    config.raw_conf.node_type = Some(cfxcore::NodeType::Full);

    let cip112_height =
        config.raw_conf.cip112_transition_height.unwrap_or(u64::MAX);
    match CIP112_TRANSITION_HEIGHT.set(cip112_height) {
        Err(e) if e != cip112_height => {
            return Err(
                "Duplicate setting for CIP-112 config with inconsistent value"
                    .to_string(),
            );
        }
        _ => {}
    }

    Ok(config)
}
