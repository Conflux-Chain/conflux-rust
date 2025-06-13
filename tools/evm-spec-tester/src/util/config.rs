use cfx_config::{Configuration, RawConfiguration};
use primitives::block_header::CIP112_TRANSITION_HEIGHT;
use std::sync::Arc;

pub fn make_configuration(
    config_file: &str,
) -> Result<Arc<Configuration>, String> {
    let mut config = Configuration::default();
    config.raw_conf = if config_file.is_empty() {
        default_raw_configuration()
    } else {
        RawConfiguration::from_file(config_file)?
    };

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

    Ok(Arc::new(config))
}

pub fn default_raw_configuration() -> RawConfiguration {
    let mut config = RawConfiguration::default();
    config.mode = Some("dev".to_string());
    config.default_transition_time = Some(1);
    config.pos_reference_enable_height = 1;
    config.align_evm_transition_height = 1;
    config.chain_id = Some(2);
    config.evm_chain_id = Some(1);
    config
}
