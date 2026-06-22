use anyhow::{Context, Result};
use cfx_minimal_mpt::{MptValueDisk, PersistedState};
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct RawCheckpoint {
    #[allow(dead_code)]
    version: u32,
    #[allow(dead_code)]
    height: u64,
    mmpt: PersistedState,
    // remaining fields ignored
}

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: ckpt_stats <checkpoint.bin>");
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read {}", path.display()))?;
    let ckpt: RawCheckpoint = bincode::deserialize(&bytes)
        .with_context(|| "deserialize checkpoint")?;
    let mmpt = ckpt.mmpt;

    let snap_count = mmpt.snapshot.len();
    let inter_count = mmpt.intermediate.len();
    let delta_count = mmpt.delta.len();

    let snap_key_bytes: usize = mmpt.snapshot.keys().map(|k| k.len()).sum();
    let snap_val_bytes: usize = mmpt.snapshot.values().map(|v| v.len()).sum();
    let inter_key_bytes: usize = mmpt.intermediate.keys().map(|k| k.len()).sum();
    let inter_val_bytes: usize = mmpt.intermediate.values().map(|v| match v {
        MptValueDisk::Some(b) => b.len(),
        MptValueDisk::Tombstone => 0,
    }).sum();
    let inter_tombstones = mmpt.intermediate.values().filter(|v| matches!(v, MptValueDisk::Tombstone)).count();
    let delta_key_bytes: usize = mmpt.delta.keys().map(|k| k.len()).sum();
    let delta_val_bytes: usize = mmpt.delta.values().map(|v| match v {
        MptValueDisk::Some(b) => b.len(),
        MptValueDisk::Tombstone => 0,
    }).sum();
    let delta_tombstones = mmpt.delta.values().filter(|v| matches!(v, MptValueDisk::Tombstone)).count();

    println!("height: {}", mmpt.height);
    println!("snapshot_epoch_count: {}", mmpt.snapshot_epoch_count);
    println!();
    println!("=== KV counts ===");
    println!("snapshot:     {:>10} entries  keys={:.1}MB  vals={:.1}MB",
        snap_count, snap_key_bytes as f64 / 1e6, snap_val_bytes as f64 / 1e6);
    println!("intermediate: {:>10} entries  keys={:.1}MB  vals={:.1}MB  tombstones={}",
        inter_count, inter_key_bytes as f64 / 1e6, inter_val_bytes as f64 / 1e6, inter_tombstones);
    println!("delta:        {:>10} entries  keys={:.1}MB  vals={:.1}MB  tombstones={}",
        delta_count, delta_key_bytes as f64 / 1e6, delta_val_bytes as f64 / 1e6, delta_tombstones);
    println!();
    println!("total:        {:>10} entries", snap_count + inter_count + delta_count);
    println!();

    // Key length distribution for snapshot
    let mut key_lens = std::collections::BTreeMap::<usize, usize>::new();
    for k in mmpt.snapshot.keys() {
        *key_lens.entry(k.len()).or_default() += 1;
    }
    println!("=== snapshot key length distribution ===");
    for (len, count) in &key_lens {
        println!("  len={:<4} count={}", len, count);
    }

    // Value length distribution (buckets)
    let bucket_labels = ["0-31", "32-63", "64-127", "128-255", "256-511", "512-1023", "1024-4095", "4096+"];
    let mut val_buckets = [0usize; 8];
    for v in mmpt.snapshot.values() {
        let i = match v.len() {
            0..=31 => 0,
            32..=63 => 1,
            64..=127 => 2,
            128..=255 => 3,
            256..=511 => 4,
            512..=1023 => 5,
            1024..=4095 => 6,
            _ => 7,
        };
        val_buckets[i] += 1;
    }
    println!();
    println!("=== snapshot value size distribution ===");
    for (label, count) in bucket_labels.iter().zip(val_buckets.iter()) {
        if *count > 0 {
            println!("  {:<12} count={}", label, count);
        }
    }

    Ok(())
}
