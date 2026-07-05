use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: ckpt-verify <checkpoint.bin>");
    let ok =
        cfx_replay_data_executor::checkpoint::Checkpoint::verify_streaming_load_matches(&path)?;
    if ok {
        eprintln!("PASS: streaming load matches full load");
    } else {
        eprintln!("FAIL: streaming load differs from full load");
        std::process::exit(1);
    }
    Ok(())
}
