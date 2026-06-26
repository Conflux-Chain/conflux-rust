use anyhow::{Context, Result};
use cfx_minimal_mpt::{PersistedState, State as MmptState};
use serde::Deserialize;
use std::{fs, path::PathBuf, time::Instant};

#[derive(Deserialize)]
struct RawCheckpoint {
    version: u32,
    height: u64,
    mmpt: PersistedState,
}

fn main() -> Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: ckpt-restore-rss <checkpoint.bin> [sleep_secs]");
    let sleep_secs: u64 = std::env::args()
        .nth(2)
        .as_deref()
        .unwrap_or("5")
        .parse()
        .context("parse sleep_secs")?;

    print_mem("start")?;
    let t = Instant::now();
    let bytes =
        fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    eprintln!(
        "read bytes={} elapsed={:.2}s",
        bytes.len(),
        t.elapsed().as_secs_f64()
    );
    print_mem("after_read")?;

    let t = Instant::now();
    let ckpt: RawCheckpoint =
        bincode::deserialize(&bytes).context("deserialize checkpoint")?;
    drop(bytes);
    eprintln!(
        "deserialized version={} checkpoint_height={} mmpt_height={} elapsed={:.2}s",
        ckpt.version,
        ckpt.height,
        ckpt.mmpt.height,
        t.elapsed().as_secs_f64()
    );
    print_mem("after_deser_drop_bytes")?;

    let t = Instant::now();
    let state = MmptState::from_persisted(ckpt.mmpt);
    eprintln!(
        "restored height={} elapsed={:.2}s",
        state.height(),
        t.elapsed().as_secs_f64()
    );
    print_mem("after_restore_drop_ckpt")?;

    std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
    print_mem("after_sleep")?;
    std::hint::black_box(&state);
    Ok(())
}

fn print_mem(label: &str) -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")
        .context("read /proc/self/status")?;
    let rss = field_kb(&status, "VmRSS").unwrap_or(0);
    let hwm = field_kb(&status, "VmHWM").unwrap_or(0);
    let vm = field_kb(&status, "VmSize").unwrap_or(0);
    let mut pss = 0;
    let mut private_dirty = 0;
    if let Ok(smaps) = fs::read_to_string("/proc/self/smaps_rollup") {
        pss = field_kb(&smaps, "Pss").unwrap_or(0);
        private_dirty = field_kb(&smaps, "Private_Dirty").unwrap_or(0);
    }
    eprintln!(
        "[mem] {label} rss_kb={rss} hwm_kb={hwm} vmsize_kb={vm} pss_kb={pss} private_dirty_kb={private_dirty}"
    );
    Ok(())
}

fn field_kb(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(name))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
}
